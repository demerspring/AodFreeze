// AddThawSpaceDlg.cpp : implementation file
//

#include "pch.h"
#include "DiskfltInst.h"
#include "AddThawSpaceDlg.h"
#include "afxdialogex.h"


// CAddThawSpaceDlg dialog

IMPLEMENT_DYNAMIC(CAddThawSpaceDlg, CDialog)

CAddThawSpaceDlg::CAddThawSpaceDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_ADDTHAWSPACE, pParent)
{

}

CAddThawSpaceDlg::~CAddThawSpaceDlg()
{
}

void CAddThawSpaceDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CAddThawSpaceDlg, CDialog)
	ON_BN_CLICKED(IDC_ADDNEW, &CAddThawSpaceDlg::OnBnClickedAddnew)
	ON_BN_CLICKED(IDC_USEEXISTING, &CAddThawSpaceDlg::OnBnClickedUseexisting)
	ON_BN_CLICKED(IDOK, &CAddThawSpaceDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BROWSE, &CAddThawSpaceDlg::OnBnClickedBrowse)
END_MESSAGE_MAP()


// CAddThawSpaceDlg message handlers

int Group1[] = { IDC_FILESIZE, IDC_CREATENEW_MAINDRIVE };
int Group2[] = { IDC_FILEPATH, IDC_BROWSE };

void CAddThawSpaceDlg::OnBnClickedAddnew()
{
	// TODO: Add your control notification handler code here
	((CButton *)GetDlgItem(IDC_USEEXISTING))->SetCheck(FALSE);
	for (int i = 0; i < _countof(Group1); i++)
		GetDlgItem(Group1[i])->EnableWindow(TRUE);
	for (int i = 0; i < _countof(Group2); i++)
		GetDlgItem(Group2[i])->EnableWindow(FALSE);
}


void CAddThawSpaceDlg::OnBnClickedUseexisting()
{
	// TODO: Add your control notification handler code here
	((CButton *)GetDlgItem(IDC_ADDNEW))->SetCheck(FALSE);
	for (int i = 0; i < _countof(Group1); i++)
		GetDlgItem(Group1[i])->EnableWindow(FALSE);
	for (int i = 0; i < _countof(Group2); i++)
		GetDlgItem(Group2[i])->EnableWindow(TRUE);
}


BOOL CAddThawSpaceDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	((CButton *)GetDlgItem(IDC_ADDNEW))->SetCheck(TRUE);
	OnBnClickedAddnew();
	CComboBox *volLetterList = (CComboBox *)GetDlgItem(IDC_VOLLETTER);
	CComboBox *mainDriveList = (CComboBox *)GetDlgItem(IDC_CREATENEW_MAINDRIVE);
	for (WCHAR i = 'C'; i <= 'Z'; i++)
	{
		if (m_volused & (1 << (i - L'A')))
			continue;
		CString strVol;
		strVol.Format(_T("%c"), i);
		UINT nType = GetDriveType(strVol + _T(":\\"));
		if (nType == DRIVE_NO_ROOT_DIR || (nType != DRIVE_FIXED && nType != DRIVE_CDROM && nType != DRIVE_UNKNOWN && nType != DRIVE_RAMDISK))
		{
			volLetterList->AddString(strVol);
		}
		else if (nType == DRIVE_FIXED)
		{
			mainDriveList->AddString(strVol);
		}
	}
	volLetterList->SetCurSel(0);
	mainDriveList->SetCurSel(0);
	GetDlgItem(IDC_FILESIZE)->SetWindowText(_T("1"));

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CAddThawSpaceDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	CString str;
	GetDlgItem(IDC_VOLLETTER)->GetWindowText(str);
	if (str.IsEmpty())
	{
		MessageBox(_T("盘符不能为空！"), _T("错误"), MB_OK | MB_ICONERROR);
		return;
	}
	m_volumeLetter = str[0];
	m_visible = !((CButton *)GetDlgItem(IDC_HIDE))->GetCheck();
	if (((CButton *)GetDlgItem(IDC_ADDNEW))->GetCheck())
	{
		GetDlgItem(IDC_CREATENEW_MAINDRIVE)->GetWindowText(str);
		if (str.IsEmpty())
		{
			MessageBox(_T("主驱动器不能为空！"), _T("错误"), MB_OK | MB_ICONERROR);
			return;
		}
		WCHAR maindrive = str[0];
		GetDlgItem(IDC_FILESIZE)->GetWindowText(str);
		m_size = _wtoll(str) * 1024ull * 1024ull * 1024ull;
		if (m_size == 0)
		{
			MessageBox(_T("大小不能为0！"), _T("错误"), MB_OK | MB_ICONERROR);
			return;
		}
		for (int i = 0; ; i++)
		{
			CString fn;
			fn.Format(_T("%c:\\DFThawSpace%c%d.dsk"), maindrive, m_volumeLetter, i);
			if (!PathFileExists(fn))
			{
				m_fileName = fn;
				break;
			}
		}
	}
	else
	{
		GetDlgItem(IDC_FILEPATH)->GetWindowText(m_fileName);
		HANDLE hFile = CreateFile(m_fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			MessageBox(_T("无法打开文件！"), _T("错误"), MB_OK | MB_ICONERROR);
			return;
		}
		LARGE_INTEGER FileSize = { 0 };
		if (!GetFileSizeEx(hFile, &FileSize))
		{
			CloseHandle(hFile);
			MessageBox(_T("无法获取文件大小！"), _T("错误"), MB_OK | MB_ICONERROR);
			return;
		}
		CloseHandle(hFile);
		m_size = FileSize.QuadPart;
	}
	CDialog::OnOK();
}


void CAddThawSpaceDlg::OnBnClickedBrowse()
{
	// TODO: Add your control notification handler code here
	CFileDialog dlg(TRUE, _T(".dsk"), _T("*.dsk"), OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, _T("解冻空间（*.dsk）|*.dsk||"), this);
	if (dlg.DoModal() == IDOK)
	{
		GetDlgItem(IDC_FILEPATH)->SetWindowText(dlg.GetPathName());
	}
}
