package main

import "syscall"

func osVersion() string {
	if v, err := syscall.Sysctl("kern.osproductversion"); err == nil {
		return "macOS " + v
	}
	if v, err := syscall.Sysctl("kern.osrelease"); err == nil {
		return "Darwin " + v
	}
	return "macOS (unknown version)"
}
