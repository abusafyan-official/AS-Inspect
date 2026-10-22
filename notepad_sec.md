# AS Inspect Technical Analysis Report

> Understand applications with evidence.

**Developer:** Developed by Abu Safyan

## 1. Executive Summary
- **Target:** `notepad.exe`
- **Path:** `C:\Windows\System32\notepad.exe`
- **Size:** 200704 bytes
- **Target Kind:** file
- **Detected Format:** pe_exe
- **Analysis Started:** 2026-10-22T10:39:08.968624+00:00
- **Total Evidence Gathered:** 46

## 2. Cryptographic Hashes
| Algorithm | Value |
|---|---|
| MD5 | `6f51bcabf1b2b34ad7e670aee6da451f` |
| SHA1 | `f3a517b07528cee3a7399386c58a9c7a59aa96b3` |
| SHA256 | `da5807bb0997cc6b5132950ec87eda2b33b1ac4533cf1f7a22a6f3b576ed7c5b` |

## 3. Architecture & Binary Attributes
- **[EV-PE-ARCH]** Architecture: x64 (64-bit AMD64) *(at FILE_HEADER.Machine)*
- **[EV-PE-ENTRY]** Entry point: 0x23bd0 *(at OPTIONAL_HEADER.AddressOfEntryPoint)*
- **[EV-PE-SEC-.text]** Section: .text (Entropy: 6.275, Size: 148992 bytes) *(at Offset 0x400)*
- **[EV-PE-SEC-.rdata]** Section: .rdata (Entropy: 5.93, Size: 37888 bytes) *(at Offset 0x24A00)*
- **[EV-PE-SEC-.data]** Section: .data (Entropy: 1.807, Size: 3584 bytes) *(at Offset 0x2DE00)*
- **[EV-PE-SEC-.pdata]** Section: .pdata (Entropy: 4.944, Size: 4608 bytes) *(at Offset 0x2EC00)*
- **[EV-PE-SEC-.didat]** Section: .didat (Entropy: 2.518, Size: 512 bytes) *(at Offset 0x2FE00)*
- **[EV-PE-SEC-.rsrc]** Section: .rsrc (Entropy: 4.612, Size: 3072 bytes) *(at Offset 0x30000)*
- **[EV-PE-SEC-.reloc]** Section: .reloc (Entropy: 4.129, Size: 1024 bytes) *(at Offset 0x30C00)*

## 4. Digital Signatures & Packing Status
- **[EV-SEC-AUTHENTICODE]** Unsigned (No Authenticode certificate table) *(Source: pe_security_directory)*

## 5. Security Capabilities & Behavior Matrix
- **[EV-CAP-File_System_Operations]** File System Operations: 4 APIs matched (CreateFileW, WriteFile, DeleteFileW, FindFirstFileW)
- **[EV-CAP-Anti-Analysis_&_Debug_Detection]** Anti-Analysis & Debug Detection: 4 APIs matched (IsDebuggerPresent, OutputDebugStringW, QueryPerformanceCounter, GetTickCount)

## 6. Framework Detection
No specific application framework indicators were detected.

## 7. Imports & Dependencies
- **[EV-PE-IMP-KERNEL32.dll]** `KERNEL32.dll (82 functions)`
- **[EV-PE-IMP-GDI32.dll]** `GDI32.dll (22 functions)`
- **[EV-PE-IMP-USER32.dll]** `USER32.dll (69 functions)`
- **[EV-PE-IMP-api-ms-win-crt-string-l1-1-0.dll]** `api-ms-win-crt-string-l1-1-0.dll (3 functions)`
- **[EV-PE-IMP-api-ms-win-crt-runtime-l1-1-0.dll]** `api-ms-win-crt-runtime-l1-1-0.dll (4 functions)`
- **[EV-PE-IMP-api-ms-win-crt-private-l1-1-0.dll]** `api-ms-win-crt-private-l1-1-0.dll (35 functions)`
- **[EV-PE-IMP-api-ms-win-core-com-l1-1-0.dll]** `api-ms-win-core-com-l1-1-0.dll (9 functions)`
- **[EV-PE-IMP-api-ms-win-core-shlwapi-legacy-l1-1-0.dll]** `api-ms-win-core-shlwapi-legacy-l1-1-0.dll (3 functions)`
- **[EV-PE-IMP-api-ms-win-shcore-obsolete-l1-1-0.dll]** `api-ms-win-shcore-obsolete-l1-1-0.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-shcore-path-l1-1-0.dll]** `api-ms-win-shcore-path-l1-1-0.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-shcore-scaling-l1-1-1.dll]** `api-ms-win-shcore-scaling-l1-1-1.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-core-rtlsupport-l1-1-0.dll]** `api-ms-win-core-rtlsupport-l1-1-0.dll (3 functions)`
- **[EV-PE-IMP-api-ms-win-core-errorhandling-l1-1-0.dll]** `api-ms-win-core-errorhandling-l1-1-0.dll (3 functions)`
- **[EV-PE-IMP-api-ms-win-core-processthreads-l1-1-0.dll]** `api-ms-win-core-processthreads-l1-1-0.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-core-processthreads-l1-1-1.dll]** `api-ms-win-core-processthreads-l1-1-1.dll (2 functions)`
- **[EV-PE-IMP-api-ms-win-core-profile-l1-1-0.dll]** `api-ms-win-core-profile-l1-1-0.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-core-sysinfo-l1-1-0.dll]** `api-ms-win-core-sysinfo-l1-1-0.dll (2 functions)`
- **[EV-PE-IMP-api-ms-win-core-interlocked-l1-1-0.dll]** `api-ms-win-core-interlocked-l1-1-0.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-core-libraryloader-l1-2-0.dll]** `api-ms-win-core-libraryloader-l1-2-0.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-core-winrt-string-l1-1-0.dll]** `api-ms-win-core-winrt-string-l1-1-0.dll (4 functions)`
- **[EV-PE-IMP-api-ms-win-core-synch-l1-1-0.dll]** `api-ms-win-core-synch-l1-1-0.dll (2 functions)`
- **[EV-PE-IMP-api-ms-win-core-winrt-error-l1-1-0.dll]** `api-ms-win-core-winrt-error-l1-1-0.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-core-string-l1-1-0.dll]** `api-ms-win-core-string-l1-1-0.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-core-winrt-l1-1-0.dll]** `api-ms-win-core-winrt-l1-1-0.dll (3 functions)`
- **[EV-PE-IMP-api-ms-win-core-winrt-error-l1-1-1.dll]** `api-ms-win-core-winrt-error-l1-1-1.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-eventing-provider-l1-1-0.dll]** `api-ms-win-eventing-provider-l1-1-0.dll (1 functions)`
- **[EV-PE-IMP-api-ms-win-core-synch-l1-2-0.dll]** `api-ms-win-core-synch-l1-2-0.dll (1 functions)`
- **[EV-PE-IMP-COMCTL32.dll]** `COMCTL32.dll (2 functions)`

## 8. URLs & Discovered Endpoints
- **[EV-STR-URL-1]** `http://schemas.microsoft.com/SMI/2016/WindowsSettings` *(Location: Offset 0x30646)*
- **[EV-STR-URL-2]** `https://go.microsoft.com/fwlink/?LinkId=834783` *(Location: Offset 0x26480)*
- **[EV-STR-URL-3]** `https://go.microsoft.com/fwlink/p/?linkid=838060` *(Location: Offset 0x26C30)*

## 9. Structured Evidence Ledger
| ID | Category | Type | Value | Confidence |
|---|---|---|---|---|
| EV-HASH-MD5 | observed | hash_md5 | `6f51bcabf1b2b34ad7e670aee6da451f` | certain |
| EV-HASH-SHA1 | observed | hash_sha1 | `f3a517b07528cee3a7399386c58a9c7a59aa96b3` | certain |
| EV-HASH-SHA256 | observed | hash_sha256 | `da5807bb0997cc6b5132950ec87eda2b33b1ac4533cf1f7a22a6f3b576ed` | certain |
| EV-PE-ARCH | observed | architecture | `x64 (64-bit AMD64)` | certain |
| EV-PE-ENTRY | observed | entry_point | `0x23bd0` | certain |
| EV-PE-SEC-.text | observed | section | `.text (Entropy: 6.275, Size: 148992 bytes)` | certain |
| EV-PE-SEC-.rdata | observed | section | `.rdata (Entropy: 5.93, Size: 37888 bytes)` | certain |
| EV-PE-SEC-.data | observed | section | `.data (Entropy: 1.807, Size: 3584 bytes)` | certain |
| EV-PE-SEC-.pdata | observed | section | `.pdata (Entropy: 4.944, Size: 4608 bytes)` | certain |
| EV-PE-SEC-.didat | observed | section | `.didat (Entropy: 2.518, Size: 512 bytes)` | certain |
| EV-PE-SEC-.rsrc | observed | section | `.rsrc (Entropy: 4.612, Size: 3072 bytes)` | certain |
| EV-PE-SEC-.reloc | observed | section | `.reloc (Entropy: 4.129, Size: 1024 bytes)` | certain |
| EV-PE-IMP-KERNEL32.dll | observed | import_dll | `KERNEL32.dll (82 functions)` | certain |
| EV-PE-IMP-GDI32.dll | observed | import_dll | `GDI32.dll (22 functions)` | certain |
| EV-PE-IMP-USER32.dll | observed | import_dll | `USER32.dll (69 functions)` | certain |
| EV-PE-IMP-api-ms-win-crt-string-l1-1-0.dll | observed | import_dll | `api-ms-win-crt-string-l1-1-0.dll (3 functions)` | certain |
| EV-PE-IMP-api-ms-win-crt-runtime-l1-1-0.dll | observed | import_dll | `api-ms-win-crt-runtime-l1-1-0.dll (4 functions)` | certain |
| EV-PE-IMP-api-ms-win-crt-private-l1-1-0.dll | observed | import_dll | `api-ms-win-crt-private-l1-1-0.dll (35 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-com-l1-1-0.dll | observed | import_dll | `api-ms-win-core-com-l1-1-0.dll (9 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-shlwapi-legacy-l1-1-0.dll | observed | import_dll | `api-ms-win-core-shlwapi-legacy-l1-1-0.dll (3 functions)` | certain |
| EV-PE-IMP-api-ms-win-shcore-obsolete-l1-1-0.dll | observed | import_dll | `api-ms-win-shcore-obsolete-l1-1-0.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-shcore-path-l1-1-0.dll | observed | import_dll | `api-ms-win-shcore-path-l1-1-0.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-shcore-scaling-l1-1-1.dll | observed | import_dll | `api-ms-win-shcore-scaling-l1-1-1.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-rtlsupport-l1-1-0.dll | observed | import_dll | `api-ms-win-core-rtlsupport-l1-1-0.dll (3 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-errorhandling-l1-1-0.dll | observed | import_dll | `api-ms-win-core-errorhandling-l1-1-0.dll (3 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-processthreads-l1-1-0.dll | observed | import_dll | `api-ms-win-core-processthreads-l1-1-0.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-processthreads-l1-1-1.dll | observed | import_dll | `api-ms-win-core-processthreads-l1-1-1.dll (2 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-profile-l1-1-0.dll | observed | import_dll | `api-ms-win-core-profile-l1-1-0.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-sysinfo-l1-1-0.dll | observed | import_dll | `api-ms-win-core-sysinfo-l1-1-0.dll (2 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-interlocked-l1-1-0.dll | observed | import_dll | `api-ms-win-core-interlocked-l1-1-0.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-libraryloader-l1-2-0.dll | observed | import_dll | `api-ms-win-core-libraryloader-l1-2-0.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-winrt-string-l1-1-0.dll | observed | import_dll | `api-ms-win-core-winrt-string-l1-1-0.dll (4 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-synch-l1-1-0.dll | observed | import_dll | `api-ms-win-core-synch-l1-1-0.dll (2 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-winrt-error-l1-1-0.dll | observed | import_dll | `api-ms-win-core-winrt-error-l1-1-0.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-string-l1-1-0.dll | observed | import_dll | `api-ms-win-core-string-l1-1-0.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-winrt-l1-1-0.dll | observed | import_dll | `api-ms-win-core-winrt-l1-1-0.dll (3 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-winrt-error-l1-1-1.dll | observed | import_dll | `api-ms-win-core-winrt-error-l1-1-1.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-eventing-provider-l1-1-0.dll | observed | import_dll | `api-ms-win-eventing-provider-l1-1-0.dll (1 functions)` | certain |
| EV-PE-IMP-api-ms-win-core-synch-l1-2-0.dll | observed | import_dll | `api-ms-win-core-synch-l1-2-0.dll (1 functions)` | certain |
| EV-PE-IMP-COMCTL32.dll | observed | import_dll | `COMCTL32.dll (2 functions)` | certain |
| EV-SEC-AUTHENTICODE | observed | authenticode_signature | `Unsigned (No Authenticode certificate table)` | certain |
| EV-CAP-File_System_Operations | observed | security_capability | `File System Operations: 4 APIs matched (CreateFileW, WriteFi` | certain |
| EV-CAP-Anti-Analysis_&_Debug_Detection | observed | security_capability | `Anti-Analysis & Debug Detection: 4 APIs matched (IsDebuggerP` | certain |
| EV-STR-URL-1 | observed | url | `http://schemas.microsoft.com/SMI/2016/WindowsSettings` | high |
| EV-STR-URL-2 | observed | url | `https://go.microsoft.com/fwlink/?LinkId=834783` | high |
| EV-STR-URL-3 | observed | url | `https://go.microsoft.com/fwlink/p/?linkid=838060` | high |

## 11. Limitations & Warnings
- None noted.