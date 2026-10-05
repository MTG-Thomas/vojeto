package main

import (
	"golang.org/x/sys/windows"
	"os"
)

// Protect the directory before writing keys; children inherit only the invoking
// Windows account and SYSTEM access. POSIX mode bits alone do not protect NTFS.
func mkdirPrivate(path string) error {
	if e := os.Mkdir(path, 0700); e != nil {
		return e
	}
	success := false
	defer func() {
		if !success {
			os.Remove(path)
		}
	}()
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	if e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); e != nil {
		return e
	}
	success = true
	return nil
}
