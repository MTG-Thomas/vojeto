//go:build !windows

package main

import "os"

func mkdirPrivate(path string) error { return os.Mkdir(path, 0700) }
