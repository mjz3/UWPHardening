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

#include "structs.h"
#include "utils.h"

#define DEVICE_NAME L"\\Device\\KMDFInjectionDriver"
#define LINK_NAME L"\\DosDevices\\KMDFInjectionDriverDriver"

NTSTATUS DefaultPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void UnloadDriver(PDRIVER_OBJECT DriverObject);

VOID OnImageLoadCallback(IN PUNICODE_STRING InFullImageName, IN HANDLE InProcessId, IN PIMAGE_INFO ImageInfo)
{
	// check If ntdll is loading
	if (InProcessId != 0 && InFullImageName != NULL && InFullImageName->Length > 0 && wcsstr(InFullImageName->Buffer, L"ntdll.dll"))
	{
		NTSTATUS status = STATUS_SUCCESS;
		PEPROCESS pProcess = NULL;
		status = PsLookupProcessByProcessId(InProcessId, &pProcess);
		BOOLEAN isWow64 = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE;


		// check if 64 bit ntdll is loading in 32 bit process
		if (isWow64 && wcsstr(InFullImageName->Buffer, L"System32"))
			return;

		// check if target process is protected
		if (PsIsProtectedProcess(pProcess))
			return;

		if (NT_SUCCESS(status))
		{
			KAPC_STATE apc;
			UNICODE_STRING ustrPath;
			PVOID pNtdll = NULL;
			PVOID LdrLoadDllLocal = NULL;

			KeStackAttachProcess(pProcess, &apc);

			// Get Ntdll address
			pNtdll = ImageInfo->ImageBase;
			
			// Get LdrLoadDll addresss
			LdrLoadDllLocal = SWIDGetModuleExport(pNtdll, "LdrLoadDll", pProcess, NULL);

			if (!LdrLoadDllLocal)
			{
				DPRINT("System Wide Injection Driver: %s: Failed to get LdrLoadDll address.\n", __FUNCTION__);
				status = STATUS_NOT_FOUND;
				KeUnstackDetachProcess(&apc);
				return;
			}

			// Call LdrLoadDll
			if (NT_SUCCESS(status))
			{
				PINJECT_BUFFER pUserBuf;
				if (isWow64)
				{
					RtlInitUnicodeString(&ustrPath, L"InjectionMitigationDLLx86.dll");
					pUserBuf = SWIDGetWow64Code(LdrLoadDllLocal, &ustrPath);
				}
				else
				{
					RtlInitUnicodeString(&ustrPath, L"InjectionMitigationDLLx64.dll");
					pUserBuf = SWIDGetNativeCode(LdrLoadDllLocal, &ustrPath);
				}

				status = SWIDApcInject(pUserBuf, (HANDLE)InProcessId);
			}

			KeUnstackDetachProcess(&apc);
		}
		else
		{
			DPRINT("System Wide Injection Driver: %s: PsLookupProcessByProcessId failed with status 0x%X.\n", __FUNCTION__, status);

			if (pProcess)
				ObDereferenceObject(pProcess);

			return;
		}

		if (pProcess)
			ObDereferenceObject(pProcess);
	}
}

NTSTATUS DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING pRegistryPath)
{
    PDEVICE_OBJECT DeviceObject;
	ULONG i;
	UNICODE_STRING uniDeviceName;
	UNICODE_STRING uniLinkName;


	DriverObject->DriverUnload = UnloadDriver;

	RtlInitUnicodeString(&uniDeviceName, DEVICE_NAME);

	RtlInitUnicodeString(&uniLinkName, LINK_NAME);

	IoCreateDevice(DriverObject, 0, &uniDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	IoCreateSymbolicLink(&uniLinkName, &uniDeviceName);
    
	

    for (i = 0 ; i <IRP_MJ_MAXIMUM_FUNCTION; i++ )
    {
        DriverObject -> MajorFunction [i] = DefaultPassThrough;
    }


	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	DeviceObject->Flags |= DO_DIRECT_IO;

	PsSetLoadImageNotifyRoutine(OnImageLoadCallback);

    return STATUS_SUCCESS;
}


NTSTATUS DefaultPassThrough (PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp -> IoStatus.Information = 0 ;
    Irp -> IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING uniLinkName;
    PDEVICE_OBJECT CurrentDeviceObject;
    PDEVICE_OBJECT NextDeviceObject;

    RtlInitUnicodeString ( & uniLinkName, LINK_NAME);

    IoDeleteSymbolicLink ( & uniLinkName);

    if (DriverObject->DeviceObject != NULL)
    {
        CurrentDeviceObject = DriverObject->DeviceObject;

        while (CurrentDeviceObject != NULL)
        {
            NextDeviceObject   = CurrentDeviceObject->NextDevice;
            IoDeleteDevice (CurrentDeviceObject);

            CurrentDeviceObject = NextDeviceObject;
        }
    }

	PsRemoveLoadImageNotifyRoutine(OnImageLoadCallback);
	
	DPRINT("System Wide Injection Driver: %s: UnloadDriver.\n", __FUNCTION__);
}
