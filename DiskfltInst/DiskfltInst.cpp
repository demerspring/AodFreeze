
// DiskfltInst.cpp : Defines the class behaviors for the application.
//

#include "pch.h"
#include "framework.h"
#include "DiskfltInst.h"
#include "DiskfltInstDlg.h"
#include "LoginDlg.h"
#include <winsvc.h>
#include <winioctl.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BOOL IsServiceRunning(WCHAR * serviceName)
{
	BOOL		ret = FALSE;
	SC_HANDLE   scmHandle = NULL;
	SC_HANDLE   serviceHandle = NULL;

	scmHandle = OpenSCManager(NULL, NULL, GENERIC_READ);

	if (NULL == scmHandle)
	{
		return ret;
	}

	serviceHandle = OpenService(scmHandle, serviceName, GENERIC_READ);

	if (NULL != serviceHandle)
	{
		SERVICE_STATUS	status;
		if (QueryServiceStatus(serviceHandle, &status))
		{
			if (SERVICE_RUNNING == status.dwCurrentState)
			{
				ret = TRUE;
			}
		}
	}

	if (scmHandle != NULL)
	{
		CloseServiceHandle(scmHandle);
	}

	if (serviceHandle != NULL)
	{
		CloseServiceHandle(serviceHandle);
	}

	return ret;
}

BOOL GetConfig(LPCWSTR passWord, PDISKFILTER_PROTECTION_CONFIG Config)
{
	DWORD dwRead = 0;
	DISKFILTER_CONTROL ControlData;
	memset(&ControlData, 0, sizeof(ControlData));
	memcpy(ControlData.AuthorizationContext, DiskFilter_AuthorizationContext, sizeof(ControlData.AuthorizationContext));
	memcpy(ControlData.Password, passWord, min(sizeof(ControlData.Password), (wcslen(passWord) + 1) * sizeof(WCHAR)));
	ControlData.ControlCode = DISKFILTER_CONTROL_GETCONFIG;
	return DeviceIoControl(_filterDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &ControlData, sizeof(ControlData), Config, sizeof(*Config), &dwRead, NULL);
}

BOOL GetStatus(LPCWSTR passWord, PBOOL protect, PBOOL allowLoadDriver)
{
	DWORD dwRead = 0;
	DISKFILTER_CONTROL ControlData;
	memset(&ControlData, 0, sizeof(ControlData));
	memcpy(ControlData.AuthorizationContext, DiskFilter_AuthorizationContext, sizeof(ControlData.AuthorizationContext));
	memcpy(ControlData.Password, passWord, min(sizeof(ControlData.Password), (wcslen(passWord) + 1) * sizeof(WCHAR)));
	ControlData.ControlCode = DISKFILTER_CONTROL_GETSTATUS;
	DISKFILTER_STATUS CurStatus;
	if (!DeviceIoControl(_filterDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &ControlData, sizeof(ControlData), &CurStatus, sizeof(CurStatus), &dwRead, NULL))
		return FALSE;
	*protect = CurStatus.ProtectEnabled;
	*allowLoadDriver = CurStatus.AllowDriverLoad;
	return TRUE;
}

// CDiskfltInstApp

BEGIN_MESSAGE_MAP(CDiskfltInstApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CDiskfltInstApp construction

CDiskfltInstApp::CDiskfltInstApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CDiskfltInstApp object

CDiskfltInstApp theApp;


// CDiskfltInstApp initialization

BOOL CDiskfltInstApp::InitInstance()
{
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	if (!IsWindows7())
	{
		MessageBox(NULL, _T("不支持的系统版本"), _T("错误"), MB_OK | MB_ICONERROR);
		return FALSE;
	}

	_filterDevice = CreateFileW(DISKFILTER_WIN32_DEVICE_NAME_W, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_filterDevice == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED)
	{
		MessageBox(NULL, _T("此程序只能同时运行一个实例"), _T("错误"), MB_OK | MB_ICONERROR);
		return FALSE;
	}
	_isDrvInstall = IsServiceRunning(SERVICE_NAME) && _filterDevice != INVALID_HANDLE_VALUE;

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("Aod"));

	if (_isDrvInstall)
	{
		while (1)
		{
			CLoginDlg dlg;
			if (dlg.DoModal() == IDOK)
			{
				dlg.m_passWord = dlg.m_passWord.Left(63);
				if (GetConfig(dlg.m_passWord, &_config))
				{
					_password = dlg.m_passWord;
					break;
				}
				else
				{
					MessageBox(NULL, _T("密码错误，请重新输入密码!"), _T("错误"), MB_OK | MB_ICONERROR);
				}
			}
			else
			{
				return FALSE;
			}
		}
		GetStatus(_password, &_protectEnabled, &_allowDriverLoad);
	}

	CDiskfltInstDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}
	else if (nResponse == -1)
	{
		TRACE(traceAppMsg, 0, "Warning: dialog creation failed, so application is terminating unexpectedly.\n");
	}


#if !defined(_AFXDLL) && !defined(_AFX_NO_MFC_CONTROLS_IN_DIALOGS)
	ControlBarCleanUp();
#endif

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}

