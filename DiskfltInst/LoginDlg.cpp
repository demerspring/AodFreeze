// LoginDlg.cpp : implementation file
//

#include "pch.h"
#include "DiskfltInst.h"
#include "LoginDlg.h"
#include "afxdialogex.h"


// CLoginDlg dialog

IMPLEMENT_DYNAMIC(CLoginDlg, CDialog)

CLoginDlg::CLoginDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_LOGIN, pParent)
{

}

CLoginDlg::~CLoginDlg()
{
}

void CLoginDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CLoginDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CLoginDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CLoginDlg message handlers


void CLoginDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	m_passWord.Empty();
	GetDlgItemText(IDC_PASSWORD, m_passWord);

#ifndef ALLOW_EMPTY_PASSWORD
	if (m_passWord.IsEmpty())
		return;
#endif

	CDialog::OnOK();
}
