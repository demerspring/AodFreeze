// AdvancedSettingDlg.cpp : implementation file
//

#include "pch.h"
#include "DiskfltInst.h"
#include "AdvancedSettingDlg.h"
#include "DiskfltInstDlg.h"
#include "afxdialogex.h"
#include "AddThawSpaceDlg.h"

#define HASH_BUFFER_SIZE (20 * 1024 * 1024) // 20MB

BOOL GetImageHash(CString strFileName, UCHAR lpHash[32])
{
	HANDLE FileHandle;
	LARGE_INTEGER FileSize;
	PUCHAR Buffer = NULL;
	BOOL bRet = FALSE;

	FileHandle = CreateFile(strFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (FileHandle == INVALID_HANDLE_VALUE)
		return FALSE;

	if (!GetFileSizeEx(FileHandle, &FileSize))
		goto out;

	LONGLONG lSize = FileSize.QuadPart;
	Buffer = (PUCHAR)malloc(HASH_BUFFER_SIZE + 40);
	if (!Buffer)
		goto out;
	*(LONGLONG*)Buffer = lSize;
	memset(Buffer + 8, 0, 32);
	if (lSize <= HASH_BUFFER_SIZE + 32)
	{
		DWORD dwRead = 0;
		if (ReadFile(FileHandle, Buffer + 8, (ULONG)lSize, &dwRead, NULL))
		{
			SHA256(Buffer, dwRead + 8, lpHash);
			bRet = TRUE;
		}
	}
	else
	{
		while (1)
		{
			DWORD dwRead = 0;
			if (!ReadFile(FileHandle, Buffer + 40, HASH_BUFFER_SIZE, &dwRead, NULL) || dwRead == 0)
				break;
			SHA256(Buffer, dwRead + 40, Buffer + 8);
		}
		SHA256(Buffer, 40, lpHash);
		bRet = TRUE;
	}
out:
	if (Buffer)
		free(Buffer);
	CloseHandle(FileHandle);
	return bRet;
}

CString GetHashString(UCHAR Hash[32])
{
	UINT *hash = (UINT*)Hash;
	CString s;
	s.Format(_T("%.8X%.8X%.8X%.8X%.8X%.8X%.8X%.8X"), hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
	return s;
}

CString GetSizeString(ULONGLONG Size)
{
	const int KB = 1024, MB = KB * 1024, GB = MB * 1024;
	CString s;
	if (Size >= GB) s.Format(_T("%.2lf GB"), 1.0 * Size / GB);
	else if (Size >= MB) s.Format(_T("%.2lf MB"), 1.0 * Size / MB);
	else if (Size >= KB) s.Format(_T("%.2lf KB"), 1.0 * Size / KB);
	else s.Format(_T("%llu B"), Size);
	return s;
}

// CAdvancedSettingDlg dialog

IMPLEMENT_DYNAMIC(CAdvancedSettingDlg, CDialog)

CAdvancedSettingDlg::CAdvancedSettingDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_ADVSET, pParent)
{

}

CAdvancedSettingDlg::~CAdvancedSettingDlg()
{
}

void CAdvancedSettingDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_DRIVER_LIST, m_driverList);
	DDX_Control(pDX, IDC_THAWSPACE_LIST, m_thawspaceList);
}


BEGIN_MESSAGE_MAP(CAdvancedSettingDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CAdvancedSettingDlg::OnBnClickedOk)
	ON_NOTIFY(NM_RCLICK, IDC_DRIVER_LIST, &CAdvancedSettingDlg::OnRclickDriverList)
	ON_NOTIFY(NM_RCLICK, IDC_THAWSPACE_LIST, &CAdvancedSettingDlg::OnRclickThawspaceList)
	ON_BN_CLICKED(IDC_DRIVER_DELSEL, &CAdvancedSettingDlg::OnBnClickedDriverDelsel)
	ON_BN_CLICKED(IDC_DRIVER_ADD, &CAdvancedSettingDlg::OnBnClickedDriverAdd)
	ON_BN_CLICKED(IDC_THAWSPACE_ADD, &CAdvancedSettingDlg::OnBnClickedThawspaceAdd)
	ON_BN_CLICKED(IDC_THAWSPACE_DEL, &CAdvancedSettingDlg::OnBnClickedThawspaceDel)
END_MESSAGE_MAP()


// CAdvancedSettingDlg message handlers


void CAdvancedSettingDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	m_settings.Flags &= ~(PROTECTION_DRIVER_BLACKLIST | PROTECTION_DRIVER_WHITELIST);
	if (((CButton *)GetDlgItem(IDC_DRIVER_WHITELIST))->GetCheck())
		m_settings.Flags |= PROTECTION_DRIVER_WHITELIST;
	else if (((CButton *)GetDlgItem(IDC_DRIVER_BLACKLIST))->GetCheck())
		m_settings.Flags |= PROTECTION_DRIVER_BLACKLIST;

	CDialog::OnOK();
}


void CAdvancedSettingDlg::OnRclickDriverList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;
}


void CAdvancedSettingDlg::OnRclickThawspaceList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;
}


BOOL CAdvancedSettingDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	if (m_settings.Flags & PROTECTION_DRIVER_WHITELIST)
		((CButton *)GetDlgItem(IDC_DRIVER_WHITELIST))->SetCheck(TRUE);
	else if (m_settings.Flags & PROTECTION_DRIVER_BLACKLIST)
		((CButton *)GetDlgItem(IDC_DRIVER_BLACKLIST))->SetCheck(TRUE);
	else
		((CButton *)GetDlgItem(IDC_DRIVER_DENY))->SetCheck(TRUE);

	struct
	{
		TCHAR *	text;
		int		width;
	} columnTableDrvlist[] =
	{
		{_T("文件名"), 400},
		{_T("校验值"), 700},
	};

	m_driverList.SetExtendedStyle(LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);

	for (int i = 0; i < _countof(columnTableDrvlist); i++)
	{
		m_driverList.InsertColumn(i, columnTableDrvlist[i].text, LVCFMT_LEFT, int(columnTableDrvlist[i].width * 1.4));
	}

	int index = 0;
	for (UCHAR i = 0; i < m_settings.DriverCount; i++)
	{
		int	nItem = m_driverList.InsertItem(index++, m_settings.DriverPath[i]);
		m_driverList.SetItemText(nItem, 1, GetHashString(m_settings.DriverList[i]));
	}

	struct
	{
		TCHAR *	text;
		int		width;
	} columnTableThawspacelist[] =
	{
		{_T("盘符"), 60},
		{_T("可见性"), 80},
		{_T("大小"), 100},
		{_T("文件名"), 400},
	};

	m_thawspaceList.SetExtendedStyle(LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);

	for (int i = 0; i < _countof(columnTableThawspacelist); i++)
	{
		m_thawspaceList.InsertColumn(i, columnTableThawspacelist[i].text, LVCFMT_LEFT, int(columnTableThawspacelist[i].width * 1.4));
	}

	index = 0;
	for (UCHAR i = 0; i < m_settings.ThawSpaceCount; i++)
	{
		WCHAR VolLetter = m_settings.ThawSpacePath[i][MAX_PATH] & ~DISKFILTER_THAWSPACE_HIDE;
		CString strVol;
		strVol.Format(_T("%c"), VolLetter);
		int	nItem = m_thawspaceList.InsertItem(index++, strVol);
		if (m_settings.ThawSpacePath[i][MAX_PATH] & DISKFILTER_THAWSPACE_HIDE)
			m_thawspaceList.SetItemText(nItem, 1, _T("隐藏"));
		else
			m_thawspaceList.SetItemText(nItem, 1, _T("可见"));
		m_thawspaceList.SetItemText(nItem, 2, GetSizeString(*(ULONGLONG*)&m_settings.ThawSpacePath[i][MAX_PATH + 1]));
		m_thawspaceList.SetItemText(nItem, 3, m_settings.ThawSpacePath[i]);
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CAdvancedSettingDlg::OnBnClickedDriverDelsel()
{
	// TODO: Add your control notification handler code here
	for (int i = 0; i < m_driverList.GetItemCount(); i++)
	{
		if (m_driverList.GetCheck(i))
		{
			m_driverList.DeleteItem(i--);
			m_settings.DriverCount--;
			for (int j = i + 1; j < m_settings.DriverCount; j++)
			{
				memcpy(m_settings.DriverList[j], m_settings.DriverList[j + 1], sizeof(m_settings.DriverList[j]));
				memcpy(m_settings.DriverPath[j], m_settings.DriverPath[j + 1], sizeof(m_settings.DriverPath[j]));
			}
		}
	}
}


void CAdvancedSettingDlg::OnBnClickedDriverAdd()
{
	// TODO: Add your control notification handler code here

	if (m_driverList.GetItemCount() >= 255)
	{
		MessageBox(_T("超出驱动个数限制！"), _T("错误"), MB_OK | MB_ICONERROR);
		return;
	}
	CFileDialog dlg(TRUE, _T(".sys"), _T("*.sys"), OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, _T("驱动文件（*.sys）|*.sys|所有文件（*.*）|*.*||"), this);
	if (dlg.DoModal() == IDOK)
	{
		CString filename = dlg.GetPathName();
		UCHAR Hash[32];
		if (!GetImageHash(filename, Hash))
		{
			MessageBox(_T("无法计算校验值！"), _T("错误"), MB_OK | MB_ICONERROR);
			return;
		}
		int	nItem = m_driverList.InsertItem(m_driverList.GetItemCount(), filename);
		m_driverList.SetItemText(nItem, 1, GetHashString(Hash));
		int cur = m_settings.DriverCount++;
		memcpy(m_settings.DriverList[cur], Hash, sizeof(Hash));
		wcscpy_s(m_settings.DriverPath[cur], filename);
	}
}


void CAdvancedSettingDlg::OnBnClickedThawspaceAdd()
{
	// TODO: Add your control notification handler code here
	if (m_thawspaceList.GetItemCount() >= 255)
	{
		MessageBox(_T("超出解冻空间个数限制！"), _T("错误"), MB_OK | MB_ICONERROR);
		return;
	}
	CAddThawSpaceDlg dlg;
	dlg.m_volused = 0;
	for (UCHAR i = 0; i < m_settings.ThawSpaceCount; i++)
	{
		WCHAR VolLetter = toupper(m_settings.ThawSpacePath[i][MAX_PATH] & ~DISKFILTER_THAWSPACE_HIDE);
		if (VolLetter >= L'A' && VolLetter <= L'Z')
			dlg.m_volused |= (1 << (VolLetter - L'A'));
	}
	if (dlg.DoModal() == IDOK)
	{
		CString strVol;
		strVol.Format(_T("%c"), dlg.m_volumeLetter);
		int	nItem = m_thawspaceList.InsertItem(m_thawspaceList.GetItemCount(), strVol);
		if (!dlg.m_visible)
			m_thawspaceList.SetItemText(nItem, 1, _T("隐藏"));
		else
			m_thawspaceList.SetItemText(nItem, 1, _T("可见"));
		m_thawspaceList.SetItemText(nItem, 2, GetSizeString(dlg.m_size));
		m_thawspaceList.SetItemText(nItem, 3, dlg.m_fileName);
		int cur = m_settings.ThawSpaceCount++;
		wcscpy_s(m_settings.ThawSpacePath[cur], MAX_PATH, dlg.m_fileName);
		m_settings.ThawSpacePath[cur][MAX_PATH - 1] = L'\0';
		m_settings.ThawSpacePath[cur][MAX_PATH] = dlg.m_volumeLetter;
		if (!dlg.m_visible)
		{
			m_settings.ThawSpacePath[cur][MAX_PATH] |= DISKFILTER_THAWSPACE_HIDE;
		}
		*(ULONGLONG*)&m_settings.ThawSpacePath[cur][MAX_PATH + 1] = dlg.m_size;
	}
}


void CAdvancedSettingDlg::OnBnClickedThawspaceDel()
{
	// TODO: Add your control notification handler code here
	for (int i = 0; i < m_thawspaceList.GetItemCount(); i++)
	{
		if (m_thawspaceList.GetCheck(i))
		{
			m_thawspaceList.DeleteItem(i--);
			m_settings.ThawSpaceCount--;
			for (int j = i + 1; j < m_settings.ThawSpaceCount; j++)
			{
				memcpy(m_settings.ThawSpacePath[j], m_settings.ThawSpacePath[j + 1], sizeof(m_settings.ThawSpacePath[j]));
			}
		}
	}
}
