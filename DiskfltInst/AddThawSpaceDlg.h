#pragma once


// CAddThawSpaceDlg dialog

class CAddThawSpaceDlg : public CDialog
{
	DECLARE_DYNAMIC(CAddThawSpaceDlg)

public:
	CAddThawSpaceDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CAddThawSpaceDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ADDTHAWSPACE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	DWORD m_volused;
	WCHAR m_volumeLetter;
	CString m_fileName;
	BOOL m_visible;
	ULONGLONG m_size;
	afx_msg void OnBnClickedAddnew();
	afx_msg void OnBnClickedUseexisting();
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedBrowse();
};
