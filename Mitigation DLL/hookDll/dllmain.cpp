//===============================================================================================//
// Copyright (c) 2017, Mojtaba Zaheri of APA Research Center, Amirkabir University of Technology
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of APA Research Center nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//

#include "mhook-lib\mhook.h"

#define MAX_SIZE 10000
char tempPath[MAX_SIZE];

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
	FILE *f;
	errno_t err = fopen_s(&f, tempPath, "a");

	if (code == EXCEPTION_ACCESS_VIOLATION) {
		fprintf_s(f, " caught ACCESS_VIOLATION .\n");
		fclose(f);
		return EXCEPTION_EXECUTE_HANDLER;
	}
	else {
		fprintf_s(f, " didn't catch ACCESS_VIOLATION.\n");
		fclose(f);
		return EXCEPTION_CONTINUE_SEARCH;
	}
}

typedef LONG(NTAPI * oNtWriteVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);

oNtWriteVirtualMemory pNtWriteVirtualMemory = (oNtWriteVirtualMemory)GetProcAddress(GetModuleHandle(L"Ntdll.dll"), "NtWriteVirtualMemory");

BOOL WINAPI MyNtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL
)
{
	__try
	{
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sign_policy;
		if (GetProcessMitigationPolicy(ProcessHandle, ProcessSignaturePolicy, &sign_policy, sizeof(sign_policy)))
		{
			//mitigation successfully received!

			if (sign_policy.Flags)
			{
				//binary mitigation is enforced in target process!

				DWORD pidSource = GetCurrentProcessId();
				DWORD pidDestination = GetProcessId(ProcessHandle);

				if (pidSource != pidDestination)
				{
					//it's an inter-process write

					if (NumberOfBytesToWrite >= sizeof(IMAGE_DOS_HEADER)) // at least 64 bytes
					{
						//writing content is large enough to contain a DOS HEADER!

						PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)Buffer;

						if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
						{
							//PIMAGE_DOS_HEADERS->e_magic is equal to "MZ"!

							PIMAGE_NT_HEADERS pINTH = (PIMAGE_NT_HEADERS)((size_t)pIDH + (size_t)pIDH->e_lfanew);

							if (pINTH->Signature == IMAGE_NT_SIGNATURE)
							{
								//PIMAGE_NT_HEADERS->Signature is equal to "PE00"!
								
								if ((pINTH->FileHeader.Characteristics) & IMAGE_FILE_DLL)
								{
									//the executable is a DLL!

									FILE *f1;
									errno_t err1 = fopen_s(&f1, tempPath, "a");
									fprintf_s(f1, "A suspicious NtWriteVirtualMemory API Call in from process %d to process %d was blocked!\n", pidSource, pidDestination);
									fclose(f1);
									SetLastError(ERROR_ACCESS_DENIED);
									return FALSE;
								}
							}
						}
					}
				}
			}
		}
	}
	__except (filter(GetExceptionCode(), GetExceptionInformation()))
	{
		FILE *f2;
		errno_t err2 = fopen_s(&f2, tempPath, "a");
		fprintf(f2, "exception occurred. ");
		fclose(f2);
	}

	return pNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten OPTIONAL);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	strcpy_s(tempPath, "C:\\Windows\\Temp\\InjectionMitigationLog.txt");

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Mhook_SetHook((PVOID*)&pNtWriteVirtualMemory, MyNtWriteVirtualMemory);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		Mhook_Unhook((PVOID*)&pNtWriteVirtualMemory); 
		break;
	}
	return TRUE;
}