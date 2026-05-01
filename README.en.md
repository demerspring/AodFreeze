# AodFreeze

> Disk seamless restore system — a lightweight disk protection tool similar to “Shadow System”.  
> Modified and enhanced from the discontinued [diskflt project](https://code.google.com/p/diskflt) (original author: dbgger).

[![Platform](https://img.shields.io/badge/platform-Windows%20XP%20~%2011-blue)]()
[![Arch](https://img.shields.io/badge/arch-x86%20|%20x64%20|%20ARM64-green)]()
[![License](https://img.shields.io/badge/license-GPLv2-lightgrey)]()

## 📖 Introduction

**AodFreeze** is a kernel-level disk restore / shadow system solution. By emulating the working principles of hardware restore cards, it implements write redirection for hard disks (partitions). All changes are automatically cleared after a reboot, effectively protecting the system from viruses, accidental operations and malware.

- Driver-level implementation, stable and efficient
- Single `.sys` file, completely green and installation-free
- Password protected; protection policies can be freely configured after entering the password

## ✨ Key Features

- **Broad system support**
  - Compatible with Windows XP SP2, Vista, 7, 8, 8.1, 10, 11.
  - Compatible with x86, x64, ARM64 (experimental) architectures

- **Comprehensive partition protection**
  - Protect only the system disk, or protect all disks (including multiple hard drives)
  - Automatic protection of MBR and GPT partition tables (partition tables on protected disks cannot be tampered with)
  - Supports protection of hidden partitions without drive letters

- **File system compatibility**
  - Supports FAT and NTFS file systems
  - Most code does not depend on file system implementation, making porting easy

- **Strong anti-penetration restore capability**
  - Blocks common Ring3 methods used to bypass restore (e.g., SCSI Passthrough, IOCTL partition table modification)
  - Integrated anti-"Machine Dog" module with configurable third-party driver interception policies

- **Flexible driver control**
  - Driver allowlist / blocklist interception, with the ability to temporarily disable or re-enable
  - When the allowlist is enabled, existing drivers on the protected disk are automatically allowed to load (system disk protection only)

- **Advanced space management**
  - ThawSpace: create persistent virtual partitions for convenient data storage
  - Direct mount: support mounting protected partitions for direct read/write
  - Save data: save data of protected partitions during system shutdown

## ⚙️ Quick Start

1. **Prepare driver signing**  
   - The project does not provide an official digital signature certificate. Please sign the driver file yourself using a code signing tool, or enable `Test Mode` on the system before loading the driver.

2. **Configure protection policies and install the driver**
   - Run the management tool (`DiskfltInst.exe`)
   - Select protection mode: system disk only / full disk / custom partitions
   - Configure driver allowlist/blocklist, ThawSpace, etc. as needed
   - Click install driver, set a password
   - Submit settings and reboot to take effect

3. **Daily use**
   - After a reboot, all changes outside thaw areas are lost and the system returns to its initial state
   - Use the buffer tool to check buffer usage
   - Temporarily mount protected partitions via the management tool for reading/writing specific files (requires prior activation of this feature)
   - Perform a one-time save of partition data via the management tool; this must be done during shutdown or restart
   - Temporary disabling of driver interception or adding exceptions does not require a reboot, but be aware of security risks

4. **Uninstallation**
   - Turn off protection via the management tool, reboot system, then uninstall the driver

## ⚠️ Important Notes

1. **Driver signing**  
   The project does not include any formal digital certificate. **You must sign the driver yourself or load it through Test Mode**, otherwise it will not run.

2. **Pre-installation checks**
   - Ensure that the protected hard disk has no file system errors or hardware failures
   - Before protecting the system disk, confirm that no Windows Update operations are in progress to avoid conflicts
   - Simultaneous use with BitLocker or device encryption is currently not supported. Please **completely disable** related features before enabling this software

3. **Driver allowlist limitations**
   - When the allowlist is enabled, only drivers that already exist on the protected disk will be automatically trusted
   - **If the system disk is not protected, the driver allowlist feature cannot be enabled** (integrity verification of system drivers relies on system disk protection)

4. **Buffer and mount risks**
   - When buffer space is insufficient, directly mounting and writing to protected partitions will overwrite existing buffer data, potentially causing system instability or even a blue screen
   - It is recommended to use mount writing only when absolutely necessary and when you have confirmed sufficient buffer space
   - Data saving is an experimental feature and conflicts with partition mounting; operate with caution. Ensure **sufficient memory** and **do not cut power during shutdown**, to avoid data loss and file system damage

5. **ThawSpace notes**
   - When adding ThawSpace, you must specify a file that **actually exists and is accessible** on the hard disk as the virtual disk file; if the file does not exist, the program may create it automatically, but the file will then become private and inaccessible to other applications
   - Avoid setting critical system files as ThawSpace virtual disk files to prevent conflicts

## 🔧 Build Guide

Please refer to [BUILD.md](BUILD.en.md) for environment requirements, compilation steps, and driver signing instructions.

## 🗺️ Future Plans

- Identify partitions using UUIDs of hard disks and partitions to avoid protection misalignment or failure caused by hardware changes
- Add the ability to exclude specific files/folders
- Improve user-mode management tools and graphical interface
- Add support for dynamic disks and REFS
- Provide more detailed logging and diagnostic features

Issues and pull requests are welcome!

## 🙏 Acknowledgements

This project is modified and enhanced based on [diskflt](https://code.google.com/p/diskflt) (original author dbgger@gmail.com). Although the original project is no longer maintained, its ideas laid the foundation for this project. Special thanks.

This project uses the open-source [filedisk](https://www.accum.se/~bosse/) (author Bo Brantén) for the virtual partition implementation. Special thanks.

This project uses the open-source [dlmalloc](https://gee.cs.oswego.edu/pub/misc/malloc.c) (author Doug Lee) as its memory manager. Special thanks.
