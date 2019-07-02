# UWP Hardening

Preventing Reflective DLL Injection on UWP Apps

Published at [OIC CERT 2018](https://www.oic-cert.org/en/download/181215%20OIC-CERT%20JCS%20Com%20v2%20181231.pdf).

About
=====

This project aims to mitigate [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection) on Microsoft UWP apps, and consists of two parts:

- **Mitigation Engine**

- **System Wide Injection Driver**

Support
=====

- **Windows 10 x64 build 14393 and higher**

Usage
=====

- **I) copy InjectionMitigationDLLx64 and InjectionMitigationDLLx86 DLLs into System32 and SysWOW64 directories respectively.**

- **II) install the driver .sys file.**
