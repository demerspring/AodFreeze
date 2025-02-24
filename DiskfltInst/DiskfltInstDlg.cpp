
// DiskfltInstDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "DiskfltInst.h"
#include "DiskfltInstDlg.h"
#include "GetPassWordDlg.h"
#include "AdvancedSettingDlg.h"
#include "afxdialogex.h"
#include <winioctl.h>
#include "ntdll.h"
#include <wininet.h>
#include "json.hpp"

#pragma comment(lib, "Wininet.lib")

#define UPDATE_VERSION _T("v3.1")
#define UPDATE_GITHUB_REPO _T("demerspring/AodFreeze")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

enum
{
	COMMAND_PROTECT,
	COMMAND_NOPROTECT,
	COMMAND_NONE,
};

enum
{
	STATE_PROTECT,
	STATE_NOPROTECT
};

typedef struct
{
	CHAR volume;
	DWORD diskNum;
	DWORD partNum;
	BOOL isProtected;
	BYTE command;
} VOLUME_INFO, *PVOLUME_INFO;

DWORD _diskNum[26], _partNum[26];
VOLUME_INFO _volInfo[MAX_PATH];
BOOL _isDrvInstall;
HANDLE _filterDevice;
DISKFILTER_PROTECTION_CONFIG _config;
CString _password;
BOOL _protectEnabled;
BOOL _allowDriverLoad;
DISKFILTER_ADVANCED_SETTINGS _advConfig;

template <typename T>
T swap_endian(T u)
{
	union
	{
		T u;
		unsigned char u8[sizeof(T)];
	} source, dest;

	source.u = u;

	for (size_t k = 0; k < sizeof(T); k++)
		dest.u8[k] = source.u8[sizeof(T) - k - 1];

	return dest.u;
}

#define rightrotate(w, n) ((w >> n) | (w) << (32-(n)))
#define copy_uint32(p, val) *((UINT32 *)p) = swap_endian<UINT32>((val))

void SHA256(const PVOID lpData, size_t ulSize, UCHAR lpOutput[32])
{
	static const UINT32 k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	UINT32 h0 = 0x6a09e667;
	UINT32 h1 = 0xbb67ae85;
	UINT32 h2 = 0x3c6ef372;
	UINT32 h3 = 0xa54ff53a;
	UINT32 h4 = 0x510e527f;
	UINT32 h5 = 0x9b05688c;
	UINT32 h6 = 0x1f83d9ab;
	UINT32 h7 = 0x5be0cd19;
	int r = (int)(ulSize * 8 % 512);
	int append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;
	size_t new_len = ulSize + append + 8;
	PUCHAR buf = (PUCHAR)malloc(new_len);
	RtlZeroMemory(buf + ulSize, append);
	RtlCopyMemory(buf, lpData, ulSize);
	buf[ulSize] = 0x80;
	size_t bits_len = ulSize * 8;
	for (int i = 0; i < 8; i++)
	{
		buf[ulSize + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
	}
	UINT32 w[64];
	RtlZeroMemory(w, sizeof(w));
	size_t chunk_len = new_len / 64;
	for (size_t idx = 0; idx < chunk_len; idx++)
	{
		UINT32 val = 0;
		for (int i = 0; i < 64; i++)
		{
			val = val | (*(buf + idx * 64 + i) << (8 * (3 - i)));
			if (i % 4 == 3)
			{
				w[i / 4] = val;
				val = 0;
			}
		}
		for (int i = 16; i < 64; i++)
		{
			UINT32 s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
			UINT32 s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		UINT32 a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
		for (int i = 0; i < 64; i++)
		{
			UINT32 s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
			UINT32 ch = (e & f) ^ (~e & g);
			UINT32 temp1 = h + s_1 + ch + k[i] + w[i];
			UINT32 s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
			UINT32 maj = (a & b) ^ (a & c) ^ (b & c);
			UINT32 temp2 = s_0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}
	copy_uint32(lpOutput, h0);
	copy_uint32(lpOutput + 1, h1);
	copy_uint32(lpOutput + 2, h2);
	copy_uint32(lpOutput + 3, h3);
	copy_uint32(lpOutput + 4, h4);
	copy_uint32(lpOutput + 5, h5);
	copy_uint32(lpOutput + 6, h6);
	copy_uint32(lpOutput + 7, h7);
	free(buf);
}

#undef rightrotate
#undef copy_uint32

BOOL WINAPI SafeIsWow64Process(HANDLE hProcess, PBOOL Wow64Process)
{
	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	static LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;

	if (fnIsWow64Process == NULL)
	{
		HMODULE hModule = GetModuleHandle(L"kernel32.dll");
		if (hModule == NULL)
		{
			return FALSE;
		}

		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hModule, "IsWow64Process");
		if (fnIsWow64Process == NULL)
		{
			return FALSE;
		}
	}
	return fnIsWow64Process(hProcess, Wow64Process);
}

BOOL Is64BitOS()
{
#if defined(_WIN64)
	return TRUE;
#elif defined(_WIN32)
	BOOL f64bitOS = FALSE;
	return (SafeIsWow64Process(GetCurrentProcess(), &f64bitOS) && f64bitOS);
#else
	return FALSE;
#endif
}

BOOL EnableDebugPrivilege(TCHAR * PName, BOOL bEnable)
{
	BOOL              result = TRUE;
	HANDLE            token;
	TOKEN_PRIVILEGES  tokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
	{
		result = FALSE;
		return result;
	}
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	LookupPrivilegeValue(NULL, PName, &tokenPrivileges.Privileges[0].Luid);
	AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		result = FALSE;
	}

	CloseHandle(token);
	return result;
}

void ShutdownWindows(DWORD dwReason)
{
	EnableDebugPrivilege(SE_SHUTDOWN_NAME, TRUE);
	ExitWindowsEx(dwReason, 0);
	EnableDebugPrivilege(SE_SHUTDOWN_NAME, FALSE);
}

BOOL GetDriveNumFromVolLetter(CHAR letter, PDWORD diskNum, PDWORD partitionNum)
{
	HANDLE hDevice;
	DWORD dwRead;
	STORAGE_DEVICE_NUMBER number;
	CHAR path[MAX_PATH];

	sprintf_s(path, "\\\\.\\%c:", letter);
	hDevice = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	if (!DeviceIoControl(hDevice, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &number, sizeof(number), &dwRead, NULL))
	{
		CloseHandle(hDevice);
		return FALSE;
	}

	*diskNum = number.DeviceNumber;
	*partitionNum = number.PartitionNumber;

	CloseHandle(hDevice);
	return TRUE;
}

CHAR GetVolLetterFromStorNum(DWORD diskNum, DWORD partNum)
{
	for (CHAR i = 'A'; i <= 'Z'; i++)
	{
		if (_diskNum[i - 'A'] == diskNum && _partNum[i - 'A'] == partNum)
		{
			return i;
		}
	}
	return 0;
}

typedef struct _FILE_FS_SIZE_INFORMATION {
	LARGE_INTEGER   TotalAllocationUnits;
	LARGE_INTEGER   AvailableAllocationUnits;
	ULONG           SectorsPerAllocationUnit;
	ULONG           BytesPerSector;
} FILE_FS_SIZE_INFORMATION, *PFILE_FS_SIZE_INFORMATION;

__int64 calcDiskUsed(DWORD diskNum, DWORD partNum)
{
	WCHAR fileName[MAX_PATH];
	swprintf_s(fileName, L"\\\\.\\Harddisk%dPartition%d", diskNum, partNum);

	HANDLE	Handle = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);

	FILE_FS_SIZE_INFORMATION info;
	IO_STATUS_BLOCK	IoStatusBlock;

	NTSTATUS status = ZwQueryVolumeInformationFile(Handle,
		&IoStatusBlock,
		&info,
		sizeof(FILE_FS_SIZE_INFORMATION),
		FileFsSizeInformation);

	DWORD _bytesPerCluster = info.BytesPerSector * info.SectorsPerAllocationUnit;

	__int64	needMemory = ((info.TotalAllocationUnits.QuadPart * info.SectorsPerAllocationUnit * 2)
		/ 8) + (info.TotalAllocationUnits.QuadPart / 8);

	CloseHandle(Handle);
	return needMemory;
}

BOOL ReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, LPCTSTR lpFileName)
{
	HGLOBAL hRes;
	HRSRC hResInfo;
	HANDLE hFile;
	DWORD dwBytes;
	hResInfo = FindResource(hModule, MAKEINTRESOURCE(wResourceID), lpType);
	if (hResInfo == NULL)
		return FALSE;
	hRes = LoadResource(hModule, hResInfo);
	if (hRes == NULL)
		return FALSE;
	hFile = CreateFile(lpFileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == NULL)
		return FALSE;

	WriteFile(hFile, hRes, SizeofResource(NULL, hResInfo), &dwBytes, NULL);

	CloseHandle(hFile);
	FreeResource(hRes);
	return TRUE;
}

BOOL ExecuteCMD(const WCHAR * cmd, DWORD * exitCode)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	WCHAR * cmdline;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	memset(&pi, 0, sizeof(pi));
	cmdline = _wcsdup(cmd);
	if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		return FALSE;
	}
	free(cmdline);

	WaitForSingleObject(pi.hProcess, INFINITE);
	if (exitCode)
	{
		GetExitCodeProcess(pi.hProcess, exitCode);
	}
	return TRUE;
}

BOOL InstallProtectDriver(const WCHAR * serviceName, const WCHAR * configPath)
{
	BOOL	ret = FALSE;
	LONG	result;
	WCHAR	sysDirPath[MAX_PATH];
	WCHAR	targetPath[MAX_PATH];

	GetSystemDirectory(sysDirPath, sizeof(sysDirPath));
	swprintf_s(targetPath, L"%s\\Drivers\\%s.sys", sysDirPath, serviceName);

#if !defined(_WIN64)
	PVOID __tmpX64_pOldVal = NULL;
	Wow64DisableWow64FsRedirection(&__tmpX64_pOldVal);
#endif
	// 释放文件
	if (Is64BitOS())
	{
		if (!ReleaseResource(NULL, IDR_DRVX64, _T("BIN"), targetPath))
		{
			return FALSE;
		}
	}
	else
	{
		if (!ReleaseResource(NULL, IDR_DRVX86, _T("BIN"), targetPath))
		{
			return FALSE;
		}
	}
#if !defined(_WIN64)
	Wow64RevertWow64FsRedirection(__tmpX64_pOldVal);
#endif

	HKEY regKey;
	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Services"),
		0,
		KEY_ALL_ACCESS,
		&regKey);

	if (SUCCEEDED(result))
	{
		HKEY subKey;
		if (SUCCEEDED(RegCreateKey(regKey, serviceName, &subKey)))
		{
			DWORD data = 0x1;
#define SET_DWORD(_key, _valueName, _data) {data = _data; RegSetValueEx(_key, _valueName, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));}
			data = 0x1;

			SET_DWORD(subKey, _T("ErrorControl"), SERVICE_ERROR_NORMAL);
			SET_DWORD(subKey, _T("Start"), SERVICE_BOOT_START);
			SET_DWORD(subKey, _T("Type"), SERVICE_KERNEL_DRIVER);
			SET_DWORD(subKey, _T("Tag"), 10);
			HKEY subsubKey;
			if (SUCCEEDED(RegCreateKey(subKey, L"Parameters", &subsubKey)))
			{
				RegSetValueEx(subsubKey, _T("ConfigPath"), NULL, REG_SZ, (LPBYTE)configPath, (wcslen(configPath) + 1) * sizeof(WCHAR));
				RegFlushKey(subsubKey);
				RegCloseKey(subsubKey);
			}
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}
		RegFlushKey(regKey);
		RegCloseKey(regKey);
	}

	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}"),
		0,
		KEY_READ | KEY_WRITE,
		&regKey);

	if (SUCCEEDED(result))
	{
		WCHAR buff[1024];
		DWORD retLen = sizeof(buff);
		ULONG type = REG_MULTI_SZ;

		memset(buff, 0, sizeof(buff));

		result = RegQueryValueEx(regKey,
			_T("UpperFilters"),
			0,
			&type,
			(LPBYTE)buff,
			&retLen);

		if (SUCCEEDED(result))
		{
			BOOL	alreadyExists = FALSE;
			WCHAR * ptr = NULL;
			for (ptr = buff; *ptr; ptr += lstrlen(ptr) + 1)
			{
				if (lstrcmpi(ptr, serviceName) == 0)
				{
					alreadyExists = TRUE;
					break;
				}
			}

			if (!alreadyExists)
			{
				DWORD	added = lstrlen(serviceName);
				memcpy(ptr, serviceName, added * sizeof(WCHAR));

				ptr += added;

				*ptr = '\0';
				*(ptr + 1) = '\0';

				result = RegSetValueEx(regKey, _T("UpperFilters"), 0, REG_MULTI_SZ, (LPBYTE)buff, retLen + ((added + 1) * sizeof(WCHAR)));
				RegFlushKey(regKey);
			}

			ret = TRUE;
		}
		RegCloseKey(regKey);
	}

	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\System"),
		0,
		KEY_ALL_ACCESS,
		&regKey);

	if (SUCCEEDED(result))
	{
		HKEY	subKey;
		if (SUCCEEDED(RegCreateKey(regKey, serviceName, &subKey)))
		{
			DWORD	data = 0x1;
			WCHAR	buff[1024];
#define SET_DWORD(_key, _valueName, _data) {data = _data; RegSetValueEx(_key, _valueName, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));}
			data = 0x1;

			SET_DWORD(subKey, _T("TypesSupported"), 7);
			wcscpy_s(buff, L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers\\DiskFilter.sys");
			RegSetValueEx(subKey, _T("EventMessageFile"), NULL, REG_EXPAND_SZ, (LPBYTE)buff, sizeof(buff));
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}
		RegFlushKey(regKey);
		RegCloseKey(regKey);
	}

	return ret;
}

void InstallMisc()
{
	LONG result;
	HKEY regKey;

	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Control\\Session Manager"),
		0,
		KEY_ALL_ACCESS,
		&regKey);

	if (SUCCEEDED(result))
	{
		WCHAR buff[1024];
		DWORD retLen = sizeof(buff);
		ULONG type = REG_MULTI_SZ;

		memset(buff, 0, sizeof(buff));

		result = RegQueryValueEx(regKey,
			_T("BootExecute"),
			0,
			&type,
			(LPBYTE)buff,
			&retLen);

		if (SUCCEEDED(result) && retLen > 0)
		{
			BOOL changed = FALSE;

			for (WCHAR * ptr = buff; *ptr && retLen > 0; )
			{
				if (StrStrW(ptr, L"autocheck autochk"))
				{
					DWORD removeLength = (lstrlen(ptr) + 1) * sizeof(WCHAR);
					memmove(ptr, (char *)ptr + removeLength, ((char *)ptr + removeLength - (char *)buff) * sizeof(WCHAR));
					retLen -= removeLength;
					changed = TRUE;
				}
				else
				{
					ptr += lstrlen(ptr) + 1;
				}
			}
			if (changed)
			{
				result = RegSetValueEx(regKey, _T("BootExecute"), 0, REG_MULTI_SZ, (LPBYTE)buff, retLen);
				RegFlushKey(regKey);
			}
		}

		HKEY subKey;
		result = ::RegOpenKeyEx(regKey,
				_T("Power"),
				0,
				KEY_ALL_ACCESS,
				&subKey);

		if (SUCCEEDED(result))
		{
			DWORD	data = 0x1;
#define SET_DWORD(_key, _valueName, _data) {data = _data; RegSetValueEx(_key, _valueName, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));}
			data = 0x1;

			SET_DWORD(subKey, _T("HiberbootEnabled"), 0);
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}

		result = ::RegOpenKeyEx(regKey,
				_T("Memory Management\\PrefetchParameters"),
				0,
				KEY_ALL_ACCESS,
				&subKey);

		if (SUCCEEDED(result))
		{
			DWORD	data = 0x1;
#define SET_DWORD(_key, _valueName, _data) {data = _data; RegSetValueEx(_key, _valueName, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));}
			data = 0x1;

			SET_DWORD(subKey, _T("EnablePrefetcher"), 0);
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}
		RegFlushKey(regKey);
		RegCloseKey(regKey);
	}

#if !defined(_WIN64)
	PVOID __tmpX64_pOldVal = NULL;
	Wow64DisableWow64FsRedirection(&__tmpX64_pOldVal);
#endif
	ExecuteCMD(L"bcdedit.exe /set {current} bootstatuspolicy ignoreallfailures", NULL);
	ExecuteCMD(L"bcdedit.exe /set {current} recoveryenabled No", NULL);
#if !defined(_WIN64)
	Wow64RevertWow64FsRedirection(__tmpX64_pOldVal);
#endif

	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"),
		0,
		KEY_ALL_ACCESS,
		&regKey);

	if (SUCCEEDED(result))
	{
		DWORD	data = 0x1;
#define SET_DWORD(_key, _valueName, _data) {data = _data; RegSetValueEx(_key, _valueName, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));}
		data = 0x1;

		SET_DWORD(regKey, _T("NoAutoUpdate"), 1);
		RegFlushKey(regKey);
		RegCloseKey(regKey);
	}
}

BOOL UninstallProtectDriver(WCHAR * serviceName)
{
	BOOL	ret = FALSE;

	WCHAR	sysDirPath[MAX_PATH];
	WCHAR	targetPath[MAX_PATH];

	GetSystemDirectory(sysDirPath, sizeof(sysDirPath));
	swprintf_s(targetPath, _T("%s\\Drivers\\%s.sys"), sysDirPath, serviceName);

#if !defined(_WIN64)
	PVOID __tmpX64_pOldVal = NULL;
	Wow64DisableWow64FsRedirection(&__tmpX64_pOldVal);
#endif
	DeleteFile(targetPath);
#if !defined(_WIN64)
	Wow64RevertWow64FsRedirection(__tmpX64_pOldVal);
#endif

	HKEY regKey;
	LONG result;
	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Services"),
		0,
		KEY_READ | KEY_WRITE,
		&regKey);
	if (ERROR_SUCCESS == result)
	{
		SHDeleteKey(regKey, serviceName);
		// 一定要flush,否则不保存
		RegFlushKey(regKey);
		RegCloseKey(regKey);
	}

	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}"),
		0,
		KEY_READ | KEY_WRITE,
		&regKey);

	if (ERROR_SUCCESS == result)
	{
		WCHAR buff[1024];
		DWORD retLen = sizeof(buff);
		ULONG type = REG_MULTI_SZ;

		memset(buff, 0, sizeof(buff));

		result = RegQueryValueEx(regKey,
			_T("UpperFilters"),
			0,
			&type,
			(LPBYTE)buff,
			&retLen);

		if (SUCCEEDED(result))
		{
			for (WCHAR * ptr = buff; *ptr; ptr += lstrlen(ptr) + 1)
			{
				if (lstrcmpi(ptr, serviceName) == 0)
				{
					DWORD removeLength = (lstrlen(ptr) + 1) * sizeof(WCHAR);
					memmove(ptr, (char *)ptr + removeLength, ((char *)ptr + removeLength - (char *)buff) * sizeof(WCHAR));

					result = RegSetValueEx(regKey, _T("UpperFilters"), 0, REG_MULTI_SZ, (LPBYTE)buff, retLen - removeLength);
					RegFlushKey(regKey);
					break;
				}
			}

			ret = TRUE;
		}
		RegCloseKey(regKey);
	}

	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\System"),
		0,
		KEY_READ | KEY_WRITE,
		&regKey);
	if (ERROR_SUCCESS == result)
	{
		SHDeleteKey(regKey, serviceName);
		RegFlushKey(regKey);
		RegCloseKey(regKey);
	}
	return ret;
}

void UninstallMisc()
{
#if !defined(_WIN64)
	PVOID __tmpX64_pOldVal = NULL;
	Wow64DisableWow64FsRedirection(&__tmpX64_pOldVal);
#endif
	ExecuteCMD(L"chkntfs.exe /D", NULL);
	ExecuteCMD(L"bcdedit.exe /set {current} bootstatuspolicy DisplayAllFailures", NULL);
	ExecuteCMD(L"bcdedit.exe /set {current} recoveryenabled Yes", NULL);
#if !defined(_WIN64)
	Wow64RevertWow64FsRedirection(__tmpX64_pOldVal);
#endif
	LONG result;
	HKEY regKey;

	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Control\\Session Manager"),
		0,
		KEY_ALL_ACCESS,
		&regKey);

	if (SUCCEEDED(result))
	{
		HKEY subKey;
		result = ::RegOpenKeyEx(regKey,
			_T("Power"),
			0,
			KEY_ALL_ACCESS,
			&subKey);

		if (SUCCEEDED(result))
		{
			DWORD	data = 0x1;
#define SET_DWORD(_key, _valueName, _data) {data = _data; RegSetValueEx(_key, _valueName, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));}
			data = 0x1;

			SET_DWORD(subKey, _T("HiberbootEnabled"), 1);
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}

		result = ::RegOpenKeyEx(regKey,
			_T("Memory Management\\PrefetchParameters"),
			0,
			KEY_ALL_ACCESS,
			&subKey);

		if (SUCCEEDED(result))
		{
			DWORD	data = 0x1;
#define SET_DWORD(_key, _valueName, _data) {data = _data; RegSetValueEx(_key, _valueName, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));}
			data = 0x1;

			SET_DWORD(subKey, _T("EnablePrefetcher"), 3);
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}
		RegCloseKey(regKey);
	}

	result = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"),
		0,
		KEY_ALL_ACCESS,
		&regKey);

	if (SUCCEEDED(result))
	{
		RegDeleteValue(regKey, _T("NoAutoUpdate"));
		RegFlushKey(regKey);
		RegCloseKey(regKey);
	}
}

BOOL InstallProtectionConfig(PDISKFILTER_PROTECTION_CONFIG Config, const WCHAR * ConfigPath)
{
	HANDLE hFile;
	DWORD dwWrite;

	hFile = CreateFileW(ConfigPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	if (!WriteFile(hFile, Config, sizeof(*Config), &dwWrite, NULL))
	{
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

BOOL ReadProtectionConfigR3(PDISKFILTER_PROTECTION_CONFIG Config, const WCHAR * ConfigPath)
{
	HANDLE hFile;
	DWORD dwRead;

	hFile = CreateFileW(ConfigPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	if (!ReadFile(hFile, Config, sizeof(*Config), &dwRead, NULL))
	{
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

BOOL IsPartitionProtected(DWORD diskNum, DWORD partNum)
{
	//if (!(_config.ProtectionFlags & PROTECTION_ENABLE))
	//	return FALSE;
	for (int i = 0; i < _config.ProtectVolumeCount; i++)
	{
		DWORD DiskNum = _config.ProtectVolume[i] & 0xFFFF;
		DWORD PartitionNum = (_config.ProtectVolume[i] >> 16) & 0xFFFF;
		if (diskNum == DiskNum && partNum == PartitionNum)
			return TRUE;
	}
	return FALSE;
}

BOOL IsVolumeProtected(WCHAR vol)
{
	if (!(_config.ProtectionFlags & PROTECTION_ENABLE))
		return FALSE;
	vol = toupper(vol);
	if (_diskNum[vol - L'A'] == -1 || _partNum[vol - L'A'] == -1)
		return FALSE;
	return IsPartitionProtected(_diskNum[vol - L'A'], _partNum[vol - L'A']);
}

BOOL IsDriverProtect()
{
	return !_allowDriverLoad;
}

void ChangeProtectState(PDISKFILTER_PROTECTION_CONFIG config, DWORD diskNum, DWORD partNum, BOOL isProtect)
{
	for (int i = 0; i < config->ProtectVolumeCount; i++)
	{
		DWORD DiskNum = config->ProtectVolume[i] & 0xFFFF;
		DWORD PartitionNum = (config->ProtectVolume[i] >> 16) & 0xFFFF;
		if (diskNum == DiskNum && partNum == PartitionNum)
		{
			if (isProtect)
			{
				return;
			}
			for (int j = i + 1; j < config->ProtectVolumeCount; j++)
			{
				config->ProtectVolume[j - 1] = config->ProtectVolume[j];
			}
			config->ProtectVolume[config->ProtectVolumeCount - 1] = 0;
			config->ProtectVolumeCount--;
			return;
		}
	}
	if (isProtect && config->ProtectVolumeCount < sizeof(config->ProtectVolume) / sizeof(*config->ProtectVolume))
	{
		config->ProtectVolume[config->ProtectVolumeCount] = (diskNum & 0xFFFF) | ((partNum & 0xFFFF) << 16);
		config->ProtectVolumeCount++;
	}
}

__int64 CalcSystemTotalNeedMemory(PDISKFILTER_PROTECTION_CONFIG Config)
{
	__int64	needMemory = 0;
	for (int i = 0; i < Config->ProtectVolumeCount; i++)
	{
		DWORD DiskNum = Config->ProtectVolume[i] & 0xFFFF;
		DWORD PartitionNum = (Config->ProtectVolume[i] >> 16) & 0xFFFF;
		needMemory += calcDiskUsed(DiskNum, PartitionNum);
	}
	// 给系统预留10M
	int	sysReserve = 1024 * 1024 * 10;
	needMemory += sysReserve;
	return needMemory;
}

BOOL ChangeProtectConfig(PDISKFILTER_PROTECTION_CONFIG Config)
{
	DWORD dwRead = 0;
	DISKFILTER_CONTROL ControlData;
	memset(&ControlData, 0, sizeof(ControlData));
	memcpy(ControlData.AuthorizationContext, DiskFilter_AuthorizationContext, sizeof(ControlData.AuthorizationContext));
	memcpy(ControlData.Password, (LPCWSTR)_password, min(sizeof(ControlData.Password), (_password.GetLength() + 1) * sizeof(WCHAR)));
	ControlData.ControlCode = DISKFILTER_CONTROL_SETCONFIG;
	memcpy(&ControlData.Config, Config, sizeof(ControlData.Config));
	return DeviceIoControl(_filterDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &ControlData, sizeof(ControlData), NULL, 0, &dwRead, NULL);
}

BOOL ChangeDriverLoadState(BOOL AllowDriverLoad)
{
	DWORD dwRead = 0;
	DISKFILTER_CONTROL ControlData;
	memset(&ControlData, 0, sizeof(ControlData));
	memcpy(ControlData.AuthorizationContext, DiskFilter_AuthorizationContext, sizeof(ControlData.AuthorizationContext));
	memcpy(ControlData.Password, (LPCWSTR)_password, min(sizeof(ControlData.Password), (_password.GetLength() + 1) * sizeof(WCHAR)));
	if (AllowDriverLoad)
		ControlData.ControlCode = DISKFILTER_CONTROL_ALLOW_DRIVER_LOAD;
	else
		ControlData.ControlCode = DISKFILTER_CONTROL_DENY_DRIVER_LOAD;
	return DeviceIoControl(_filterDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &ControlData, sizeof(ControlData), NULL, 0, &dwRead, NULL);
}

// CDiskfltInstDlg dialog

CDiskfltInstDlg::CDiskfltInstDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_MAINDLG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDiskfltInstDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_VOLUMELIST, m_volumeList);
	DDX_Control(pDX, IDC_COMMAND, m_command);
}

BEGIN_MESSAGE_MAP(CDiskfltInstDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CDiskfltInstDlg::OnBnClickedOK)
	ON_BN_CLICKED(IDCANCEL, &CDiskfltInstDlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_INSTALLSYS, &CDiskfltInstDlg::OnBnClickedInstallsys)
	ON_BN_CLICKED(IDC_APPLY, &CDiskfltInstDlg::OnBnClickedApply)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_VOLUMELIST, &CDiskfltInstDlg::OnItemchangedVolumelist)
	ON_BN_CLICKED(IDC_MODIFYPWD, &CDiskfltInstDlg::OnBnClickedModifypwd)
	ON_BN_CLICKED(IDC_EXIT, &CDiskfltInstDlg::OnBnClickedExit)
	ON_BN_CLICKED(IDC_PROTECTSYS, &CDiskfltInstDlg::OnBnClickedProtectsys)
	ON_CBN_SELCHANGE(IDC_COMMAND, &CDiskfltInstDlg::OnSelchangeCommand)
	ON_BN_CLICKED(IDC_ADVANCEDSETTING, &CDiskfltInstDlg::OnBnClickedAdvancedsetting)
	ON_BN_CLICKED(IDC_CHECKUPDATE, &CDiskfltInstDlg::OnBnClickedCheckupdate)
END_MESSAGE_MAP()


// CDiskfltInstDlg message handlers

BOOL CDiskfltInstDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	memset(_diskNum, -1, sizeof(_diskNum));
	memset(_partNum, -1, sizeof(_partNum));
	for (CHAR i = 'A'; i <= 'Z'; i++)
	{
		GetDriveNumFromVolLetter(i, &_diskNum[i - 'A'], &_partNum[i - 'A']);
	}

	if (!_isDrvInstall)
	{
		WCHAR sysDir[MAX_PATH];
		GetSystemDirectoryW(sysDir, sizeof(sysDir));

		GetDlgItem(IDC_APPLY)->EnableWindow(FALSE);
		GetDlgItem(IDC_MODIFYPWD)->EnableWindow(FALSE);
		CStringW ConfigPath;
		ConfigPath.Format(L"%c:\\DFConfig.sys", sysDir[0]);
		ReadProtectionConfigR3(&_config, ConfigPath);
		if (_config.Magic != DISKFILTER_CONFIG_MAGIC || _config.Version != DISKFILTER_DRIVER_VERSION || 
			IDYES != MessageBox(_T("是否读取已有的还原配置?"), _T("询问"), MB_YESNO | MB_ICONQUESTION))
		{
			memset(&_config, 0, sizeof(_config));
		}
		if (_config.Magic != DISKFILTER_CONFIG_MAGIC || _config.Version != DISKFILTER_DRIVER_VERSION)
		{
			_config.ProtectionFlags = PROTECTION_ENABLE | PROTECTION_DRIVER_WHITELIST | PROTECTION_ALLOW_DRIVER_LOAD;
			_allowDriverLoad = TRUE;
			ChangeProtectState(&_config, _diskNum[sysDir[0] - 'A'], _partNum[sysDir[0] - 'A'], TRUE);
		}
		else
		{
			_allowDriverLoad = (_config.ProtectionFlags & PROTECTION_ALLOW_DRIVER_LOAD) ? TRUE : FALSE;
		}
	}
	else
	{
		SetDlgItemText(IDC_INSTALLSYS, _T("卸载驱动"));
	}
	((CButton *)GetDlgItem(IDC_PROTECTSYS))->SetCheck(IsDriverProtect());
	((CButton *)GetDlgItem(IDC_ENABLE_PROTECT))->SetCheck((_config.ProtectionFlags & PROTECTION_ENABLE) ? TRUE : FALSE);
	((CButton *)GetDlgItem(IDC_ENABLE_THAWSPACE))->SetCheck((_config.ProtectionFlags & PROTECTION_ENABLE_THAWSPACE) ? TRUE : FALSE);
	_advConfig.Flags = _config.ProtectionFlags & (PROTECTION_DRIVER_WHITELIST | PROTECTION_DRIVER_BLACKLIST);
	_advConfig.DriverCount = _config.DriverCount;
	memcpy(_advConfig.DriverList, _config.DriverList, sizeof(_config.DriverList));
	memcpy(_advConfig.DriverPath, _config.DriverPath, sizeof(_config.DriverPath));
	_advConfig.ThawSpaceCount = _config.ThawSpaceCount;
	memcpy(_advConfig.ThawSpacePath, _config.ThawSpacePath, sizeof(_config.ThawSpacePath));

	struct
	{
		TCHAR *	text;
		int		width;
	} columnTable[] =
	{
		{_T("盘符"),		60},
		{_T("分区类型"),	65},
		{_T("总空间(MB)"),	80},
		{_T("已使用(MB)"),	80},
		{_T("状态"),	60},
		{_T("命令"),	60},
	};

	m_command.SetItemData(m_command.AddString(_T("保护")), COMMAND_PROTECT);
	m_command.SetItemData(m_command.AddString(_T("不保护")), COMMAND_NOPROTECT);
	m_command.SetItemData(m_command.AddString(_T("无命令")), COMMAND_NONE);
	m_command.SetCurSel(2);

	m_volumeList.SetExtendedStyle(LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);

	for (int i = 0; i < _countof(columnTable); i++)
	{
		m_volumeList.InsertColumn(i, columnTable[i].text, LVCFMT_LEFT, int(columnTable[i].width * 1.4));
	}

	HKEY hKEY = NULL;
	long lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"), 0, KEY_READ, &hKEY);
	if (lRet == ERROR_SUCCESS)
	{
		int iSize = 0;
		DWORD dwType;
		DWORD dwDiskCount;
		DWORD dwBufLen = sizeof(DWORD);
		lRet = ::RegQueryValueEx(hKEY, _T("Count"), NULL, &dwType, (BYTE *)&dwDiskCount, &dwBufLen);
		if (lRet == ERROR_SUCCESS)
		{
			int index = 0, volcount = 0;
			for (DWORD i = 0; i < dwDiskCount; i++)
			{
				WCHAR szDiskName[MAX_PATH] = { 0 };
				wsprintf(szDiskName, L"\\\\.\\PhysicalDrive%d", i);

				DWORD nDiskBytesRead = 0;
				DWORD dwSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) * 10;
				PDRIVE_LAYOUT_INFORMATION_EX DiskPartInfo = (PDRIVE_LAYOUT_INFORMATION_EX)malloc(dwSize);
				ZeroMemory(DiskPartInfo, dwSize);
				DWORD PartitionStyle = PARTITION_STYLE_RAW;

				HANDLE hDisk = CreateFileW(szDiskName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

				if (hDisk != INVALID_HANDLE_VALUE)
				{
					BOOL fRet = DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, DiskPartInfo, dwSize, &nDiskBytesRead, NULL);
					if (!fRet && GetLastError() == ERROR_BUFFER_OVERFLOW)
					{
						dwSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * (DiskPartInfo->PartitionCount + 1);
						DiskPartInfo = (PDRIVE_LAYOUT_INFORMATION_EX)realloc(DiskPartInfo, dwSize);
						ZeroMemory(DiskPartInfo, dwSize);
						fRet = DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, DiskPartInfo, dwSize, &nDiskBytesRead, NULL);
					}
					CloseHandle(hDisk);
					if (fRet)
					{
						PartitionStyle = DiskPartInfo->PartitionStyle;
						DWORD dwPartitionCount = DiskPartInfo->PartitionCount;
						for (DWORD j = 0; j < dwPartitionCount; j++)
						{
							if (PartitionStyle == PARTITION_STYLE_MBR && DiskPartInfo->PartitionEntry[j].Mbr.PartitionType == PARTITION_ENTRY_UNUSED)
								continue;
							CHAR drive = GetVolLetterFromStorNum(i, j + 1);
							WCHAR drvpth[MAX_PATH];
							swprintf_s(drvpth, L"%C:\\", drive);
							WCHAR buff[256];
							if (drive)
							{
								swprintf_s(buff, L"%C", drive);
							}
							else
							{
								swprintf_s(buff, L"(%d,%d)", i, j + 1);
							}
							int	nItem = m_volumeList.InsertItem(index++, buff);
							// 磁盘类型
							if (drive && GetVolumeInformationW(drvpth, NULL, 0, NULL, NULL, NULL, buff, MAX_PATH))
							{
								m_volumeList.SetItemText(nItem, 1, buff);
							}

							// 磁盘大小
							BOOL isProtect = IsPartitionProtected(i, j + 1);

							unsigned __int64 HDAmount = 0;
							unsigned __int64 HDFreeSpace = 0;

							if (GetDiskFreeSpaceEx(drvpth, (PULARGE_INTEGER)&HDFreeSpace, (PULARGE_INTEGER)&HDAmount, NULL))
							{
								swprintf_s(buff, L"%d", (unsigned long)(HDAmount / 1024 / 1024));
								m_volumeList.SetItemText(nItem, 2, buff);

								swprintf_s(buff, L"%d", (unsigned long)((HDAmount - HDFreeSpace) / 1024 / 1024));
								m_volumeList.SetItemText(nItem, 3, buff);
							}
							
							if (isProtect)
							{
								m_volumeList.SetItemText(nItem, 4, _T("保护"));
							}
							else
							{
								m_volumeList.SetItemText(nItem, 4, _T("不保护"));
							}

							m_volumeList.SetItemText(nItem, 5, _T("无命令"));

							VOLUME_INFO volumeInfo;
							volumeInfo.volume = drive;
							volumeInfo.diskNum = i;
							volumeInfo.partNum = j + 1;
							volumeInfo.isProtected = isProtect;
							volumeInfo.command = COMMAND_NONE;

							_volInfo[volcount] = volumeInfo;
							m_volumeList.SetItemData(nItem, volcount);
							volcount++;
						}
					}
					free(DiskPartInfo);
				}
			}
		}
		if (hKEY != NULL)
			RegCloseKey(hKEY);
	}

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CDiskfltInstDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CDiskfltInstDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CDiskfltInstDlg::OnBnClickedOK()
{
	// TODO: Add your control notification handler code here
}


void CDiskfltInstDlg::OnBnClickedCancel()
{
	// TODO: Add your control notification handler code here
	CDialog::OnCancel();
}


void CDiskfltInstDlg::OnBnClickedInstallsys()
{
	// TODO: Add your control notification handler code here
	BOOL ret = FALSE;
	TCHAR sysDir[MAX_PATH];
	GetSystemDirectory(sysDir, sizeof(sysDir));

	if (!_isDrvInstall)
	{
		CGetPassWordDlg	dlg;
		dlg.setMode(CGetPassWordDlg::MODE_INIT);
		if (IDOK == dlg.DoModal())
		{
			memset(&_config, 0, sizeof(_config));
			DISKFILTER_PROTECTION_CONFIG conf;
			__int64 needMemory;
			if (GetConfigFromControls(&conf, &needMemory))
			{
				conf.Magic = DISKFILTER_CONFIG_MAGIC;
				conf.Version = DISKFILTER_DRIVER_VERSION;
				SHA256((PVOID)(LPCWSTR)dlg.m_passWord, dlg.m_passWord.GetLength() * sizeof(WCHAR), conf.Password);

				CStringW ConfigPath;
				ConfigPath.Format(L"%c:\\DFConfig.sys", sysDir[0]);
				ret = InstallProtectionConfig(&conf, ConfigPath);

				if (ret)
				{
					ret = InstallProtectDriver(SERVICE_NAME, ConfigPath.GetBuffer(MAX_PATH));
					ConfigPath.ReleaseBuffer();
					InstallMisc();
				}
			}
		}
		else
		{
			return;
		}
	}
	else
	{
		if (IsVolumeProtected(sysDir[0]))
		{
			MessageBox(_T("请在系统盘未受保护的情况下卸载还原!"), _T("错误"), MB_OK | MB_ICONERROR);
			return;
		}
		else
		{
			if (IDOK != MessageBox(_T("确认是否卸载?"), _T("询问"), MB_OKCANCEL | MB_ICONQUESTION))
			{
				return;
			}
			ret = UninstallProtectDriver(SERVICE_NAME);
			UninstallMisc();
			if (IDYES != MessageBox(_T("是否保留还原配置?"), _T("询问"), MB_YESNO | MB_ICONQUESTION))
			{
				DISKFILTER_PROTECTION_CONFIG conf;
				memset(&conf, 0, sizeof(conf));
				ChangeProtectConfig(&conf);
			}
		}

	}

	if (ret)
	{
		MessageBox(_T("操作成功,系统将重新启动!"), _T("提示"), MB_OK | MB_ICONWARNING);
		ShutdownWindows(EWX_REBOOT | EWX_FORCE);
	}
	else
	{
		CString str;
		str.Format(_T("操作失败!错误代码:%d"), GetLastError());
		MessageBox(str, _T("错误"), MB_OK | MB_ICONERROR);
	}
}


void CDiskfltInstDlg::OnBnClickedApply()
{
	// TODO: Add your control notification handler code here
	if (!_isDrvInstall)
		return;

	DISKFILTER_PROTECTION_CONFIG protectInfo;
	__int64 needMemory;
	if (GetConfigFromControls(&protectInfo, &needMemory))
	{
		CString str;
		if (ChangeProtectConfig(&protectInfo))
		{
			str.Format(_T("提示 (总内存需要 %.2lf MB)"), needMemory / 1024.0 / 1024.0);
			MessageBox(_T("操作成功,系统将重新启动!"), str, MB_OK | MB_ICONWARNING);
			ShutdownWindows(EWX_REBOOT | EWX_FORCE);
		}
		else
		{
			str.Format(_T("操作失败!错误代码:%d"), GetLastError());
			MessageBox(str, _T("错误"), MB_OK | MB_ICONERROR);
		}
	}
}


void CDiskfltInstDlg::OnItemchangedVolumelist(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;
}


void CDiskfltInstDlg::OnBnClickedModifypwd()
{
	// TODO: Add your control notification handler code here
	if (!_isDrvInstall)
		return;

	BOOL ret = FALSE;
	CGetPassWordDlg dlg;
	dlg.setMode(CGetPassWordDlg::MODE_MODIFY);
	if (dlg.DoModal() == IDOK)
	{
		DISKFILTER_PROTECTION_CONFIG protectInfo;
		memcpy(&protectInfo, &_config, sizeof(protectInfo));

		dlg.m_passWord = dlg.m_passWord.Left(63);
		SHA256((PVOID)(LPCWSTR)dlg.m_passWord, dlg.m_passWord.GetLength() * sizeof(WCHAR), protectInfo.Password);
		if (dlg.m_oldPassWord != _password)
		{
			MessageBox(_T("原密码错误!"), _T("错误"), MB_OK | MB_ICONERROR);
			return;
		}
		ret = ChangeProtectConfig(&protectInfo);

		if (ret)
		{
			MessageBox(_T("操作成功,系统将重新启动!"), _T("提示"), MB_OK | MB_ICONWARNING);
			ShutdownWindows(EWX_REBOOT | EWX_FORCE);
		}
		else
		{
			CString str;
			str.Format(_T("操作失败!错误代码:%d"), GetLastError());
			MessageBox(str, _T("错误"), MB_OK | MB_ICONERROR);
		}
	}
}


void CDiskfltInstDlg::OnBnClickedExit()
{
	// TODO: Add your control notification handler code here
	OnBnClickedCancel();
}


void CDiskfltInstDlg::OnBnClickedProtectsys()
{
	// TODO: Add your control notification handler code here
	_allowDriverLoad = !((CButton *)GetDlgItem(IDC_PROTECTSYS))->GetCheck();
	if (!_isDrvInstall)
		return;
	if (!ChangeDriverLoadState(_allowDriverLoad))
	{
		CString str;
		str.Format(_T("操作失败!错误代码:%d"), GetLastError());
		MessageBox(str, _T("错误"), MB_OK | MB_ICONERROR);
	}
}


void CDiskfltInstDlg::OnSelchangeCommand()
{
	// TODO: Add your control notification handler code here
	TCHAR commandStr[256];
	m_command.GetLBText(m_command.GetCurSel(), commandStr);

	DWORD command = m_command.GetItemData(m_command.GetCurSel());

	for (int i = 0; i < m_volumeList.GetItemCount(); i++)
	{
		if (m_volumeList.GetCheck(i))
		{
			PVOLUME_INFO volumeInfo = &_volInfo[m_volumeList.GetItemData(i)];
			volumeInfo->command = (BYTE)command;
			m_volumeList.SetItemText(i, 5, commandStr);
		}
	}
}

BOOL CDiskfltInstDlg::GetConfigFromControls(PDISKFILTER_PROTECTION_CONFIG Config, __int64 *NeedMemory)
{
	// TODO: Add your implementation code here.
	int count = m_volumeList.GetItemCount();

	DISKFILTER_PROTECTION_CONFIG protectInfo;
	memcpy(&protectInfo, &_config, sizeof(protectInfo));

	protectInfo.ProtectionFlags &= ~(PROTECTION_DRIVER_BLACKLIST | PROTECTION_DRIVER_WHITELIST);
	protectInfo.ProtectionFlags |= _advConfig.Flags;
	protectInfo.DriverCount = _advConfig.DriverCount;
	memcpy(protectInfo.DriverList, _advConfig.DriverList, sizeof(protectInfo.DriverList));
	memcpy(protectInfo.DriverPath, _advConfig.DriverPath, sizeof(protectInfo.DriverPath));
	protectInfo.ThawSpaceCount = _advConfig.ThawSpaceCount;
	memcpy(protectInfo.ThawSpacePath, _advConfig.ThawSpacePath, sizeof(protectInfo.ThawSpacePath));

	if (_allowDriverLoad)
	{
		protectInfo.ProtectionFlags |= PROTECTION_ALLOW_DRIVER_LOAD;
	}
	else
	{
		protectInfo.ProtectionFlags &= ~PROTECTION_ALLOW_DRIVER_LOAD;
	}

	if (((CButton *)GetDlgItem(IDC_ENABLE_PROTECT))->GetCheck())
		protectInfo.ProtectionFlags |= PROTECTION_ENABLE;
	else
		protectInfo.ProtectionFlags &= ~PROTECTION_ENABLE;

	if (((CButton *)GetDlgItem(IDC_ENABLE_THAWSPACE))->GetCheck())
		protectInfo.ProtectionFlags |= PROTECTION_ENABLE_THAWSPACE;
	else
		protectInfo.ProtectionFlags &= ~PROTECTION_ENABLE_THAWSPACE;

	for (int i = 0; i < count; i++)
	{
		PVOLUME_INFO volumeInfo = &_volInfo[m_volumeList.GetItemData(i)];

		BOOL isProtect = FALSE;
		if (COMMAND_PROTECT == volumeInfo->command)
		{
			isProtect = TRUE;
		}
		else if (COMMAND_NOPROTECT == volumeInfo->command)
		{
			isProtect = FALSE;
		}
		else if (COMMAND_NONE == volumeInfo->command)
		{
			isProtect = volumeInfo->isProtected;
		}

		ChangeProtectState(&protectInfo, volumeInfo->diskNum, volumeInfo->partNum, isProtect);
	}

	if (_config.Magic == DISKFILTER_CONFIG_MAGIC && _config.Version == DISKFILTER_DRIVER_VERSION && memcmp(&protectInfo, &_config, sizeof(protectInfo)) == 0)
	{
		MessageBox(_T("配置没有发生任何改变!"), _T("提示"), MB_OK | MB_ICONWARNING);
		return FALSE;
	}

	__int64	needMemory = CalcSystemTotalNeedMemory(&protectInfo);

	MEMORYSTATUS memStatus;
	memStatus.dwLength = sizeof(MEMORYSTATUS);
	GlobalMemoryStatus(&memStatus);

	__int64	added = (needMemory - memStatus.dwAvailPhys) / 1024 / 1024;

	CString	str;
	if (needMemory >= memStatus.dwAvailPhys)
	{
		str.Format(_T("物理内存可用空间太小, 最少需要再增加 %lld MB !"), added);
		MessageBox(str, _T("错误"), MB_OK | MB_ICONERROR);
		return FALSE;
	}
	memcpy(Config, &protectInfo, sizeof(protectInfo));
	*NeedMemory = needMemory;
	return TRUE;
}


void CDiskfltInstDlg::OnBnClickedAdvancedsetting()
{
	// TODO: Add your control notification handler code here
	CAdvancedSettingDlg dlg;
	memcpy(&dlg.m_settings, &_advConfig, sizeof(_advConfig));
	if (dlg.DoModal() == IDOK)
	{
		memcpy(&_advConfig, &dlg.m_settings, sizeof(_advConfig));
	}
}

BOOL CheckUpdate(CString& ver, CString& name, CString& info)
{
	HINTERNET hSession = InternetOpen(_T("UpdateChecker"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	BOOL flag = FALSE;
	if (hSession)
	{
		HINTERNET hHttp = InternetOpenUrl(hSession, _T("https://api.github.com/repos/") UPDATE_GITHUB_REPO _T("/releases/latest"), NULL, 0, INTERNET_FLAG_RELOAD, 0);
		if (hHttp)
		{
			char buf[1024];
			std::string response;
			DWORD dwSize;
			do
			{
				InternetReadFile(hHttp, buf, sizeof(buf) - 1, &dwSize);
				if (dwSize > 0)
				{
					buf[dwSize - 1] = '\0';
					response += buf;
				}
			} while (dwSize > 0);
			InternetCloseHandle(hHttp);
			tiny::TinyJson json;
			json.ReadJson(response);
			ver = json.Get<std::string>("tag_name").c_str();
			name = json.Get<std::string>("name").c_str();
			info = json.Get<std::string>("body").c_str();
			info.Replace(L"\\r", L"\r");
			info.Replace(L"\\n", L"\n");
			info.Replace(L"\\t", L"\t");
			if (ver > UPDATE_VERSION)
				flag = TRUE;
		}
		InternetCloseHandle(hSession);
	}
	return flag;
}

void CDiskfltInstDlg::OnBnClickedCheckupdate()
{
	// TODO: Add your control notification handler code here
	CString ver, name, info;
	if (CheckUpdate(ver, name, info))
	{
		if (_isDrvInstall)
		{
			TCHAR sysDir[MAX_PATH];
			GetSystemDirectory(sysDir, sizeof(sysDir));
			if (IsVolumeProtected(sysDir[0]))
			{
				MessageBox(_T("有新的版本:") + name + _T(", 请在系统盘未受保护的情况下进行更新!"), _T("提示"), MB_OK | MB_ICONINFORMATION);
				return;
			}
		}
		if (MessageBox(_T("有新的版本:") + name + _T(", 是否下载?\r\n") + info, _T("提示"), MB_OKCANCEL | MB_ICONQUESTION) == IDOK)
		{
			ShellExecute(NULL, _T("open"), _T("https://github.com/") UPDATE_GITHUB_REPO _T("/releases/latest"), NULL, NULL, SW_SHOWNORMAL);
		}
	}
	else
	{
		MessageBox(_T("无可用更新!"), _T("提示"), MB_OK | MB_ICONINFORMATION);
	}
}
