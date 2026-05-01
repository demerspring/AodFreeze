# Compilation Guide

## 1. Environment Preparation
Install the following build tools:
- WDK 10.0.19041.5738
- Visual Studio 2019
  - Windows 10 SDK 10.0.19041.0
  - MSVC v142 - VS 2019 C++ x64/x86 build tools
  - MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (Latest)
  - C++ MFC for latest v142 build tools (x86 & x64)
  - C++ MFC for latest v142 build tools with Spectre Mitigations (x86 & x64)
  - C++ Windows XP Support for VS 2017 (v141) tools
  - Optional ARM64 components: MSVC v142 - VS 2019 C++ ARM64 build tools
  - Optional ARM64 components: MSVC v142 - VS 2019 C++ ARM64 Spectre-mitigated libs (Latest)
  - Optional ARM64 components: C++ MFC for latest v142 build tools (ARM64)
  - Optional ARM64 components: C++ MFC for latest v142 build tools with Spectre Mitigations (ARM64)

## 2. Compilation
Open `DiskFilter.sln` and follow these steps:
1. Build `DiskFilter` for x86 and x64 (optionally build for ARM64)
2. Run `copydrivers.bat`
3. Sign `DistDriver\i386\diskflt.sys` and `DistDriver\amd64\diskflt.sys` (optionally sign for ARM64)
4. Build `DiskfltInst`, `diskfltmgmt`, `DiskfltBufmon` for x86 and x64 (optionally build for ARM64)

### Common Compilation Error Fixes
If you encounter a `wchar.h:642` error when building the `DiskFilter` driver, it is a WDK issue, and you need to modify `wchar.h` yourself.
```diff
642c642
< __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1(errno_t, _cgetws_s, _Post_readable_size_(*_Size) wchar_t, _Buffer, size_t *, _Size)
---
> __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1(errno_t, _cgetws_s, _Post_readable_size_(*_Size) wchar_t, _Buffer, size_t *, _SizeRead)
```

## 3. Testing
It is recommended to test in a virtual machine. Before testing, disable BitLocker, Secure Boot, all antivirus software, and any software that can prevent driver installation. If you do not have a formal driver signature, you need to enable test mode.

### Handling Test Failures
Boot into Windows PE, mount the system drive as C:, first run `chkdsk.exe /f C:` to repair the file system, then run `diskfltmgmt.exe --password none uninstall --offline-directory C:\Windows` to uninstall.

