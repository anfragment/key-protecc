package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// osVersion reports the kernel's own version numbers (RtlGetVersion is exempt from
// manifest-based version lying). Builds >= 22000 are Windows 11.
func osVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("Windows %d.%d build %d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
