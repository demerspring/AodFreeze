#pragma once


// CGetPassWordDlg dialog

class CGetPassWordDlg : public CDialog
{
	DECLARE_DYNAMIC(CGetPassWordDlg)

public:
	enum { MODE_INIT, MODE_MODIFY };
	CString	m_passWord;
	CString m_oldPassWord;
	void setMode(ULONG mode);
	CGetPassWordDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CGetPassWordDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_GETPASS };
#endif

protected:
	ULONG	m_Mode;

	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedOk();
};
