package main

import (
	"os"
	"strings"
)

func osVersion() string {
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "Linux (unknown kernel)"
	}
	return "Linux " + strings.TrimSpace(string(release))
}
