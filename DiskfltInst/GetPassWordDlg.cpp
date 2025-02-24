// GetPassWordDlg.cpp : implementation file
//

#include "pch.h"
#include "DiskfltInst.h"
#include "GetPassWordDlg.h"
#include "afxdialogex.h"


// CGetPassWordDlg dialog

IMPLEMENT_DYNAMIC(CGetPassWordDlg, CDialog)

CGetPassWordDlg::CGetPassWordDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_GETPASS, pParent)
{

}

CGetPassWordDlg::~CGetPassWordDlg()
{
}

void CGetPassWordDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CGetPassWordDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CGetPassWordDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CGetPassWordDlg message handlers

void CGetPassWordDlg::setMode(ULONG mode)
{
	m_Mode = mode;
}

BOOL CGetPassWordDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	if (MODE_INIT == m_Mode)
	{
		GetDlgItem(IDC_CURRENT_PWD)->EnableWindow(FALSE);
		GetDlgItem(IDC_NEW_PWD)->SetFocus();
	}
	else
	{
		GetDlgItem(IDC_CURRENT_PWD)->SetFocus();
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CGetPassWordDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	TCHAR oldPassWord[256];
	TCHAR newPassWord[256];
	TCHAR confirmPassWord[256];
	GetDlgItemText(IDC_CURRENT_PWD, oldPassWord, sizeof(oldPassWord));
	GetDlgItemText(IDC_NEW_PWD, newPassWord, sizeof(newPassWord));
	GetDlgItemText(IDC_CONFIRM_PWD, confirmPassWord, sizeof(confirmPassWord));
	if (0 != lstrcmpi(newPassWord, confirmPassWord))
	{
		MessageBox(_T("两次输入密码不一致, 请重新输入!"), _T("错误"), MB_OK | MB_ICONERROR);
		return;
	}
	if (0 == lstrlen(newPassWord))
	{
		return;
	}
	if ((MODE_MODIFY == m_Mode) && (0 == lstrlen(oldPassWord)))
	{
		return;
	}
	m_passWord = newPassWord;
	m_oldPassWord = oldPassWord;
	CDialog::OnOK();
}
