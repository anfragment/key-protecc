package main

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"runtime"
	"runtime/debug"
	"slices"
	"time"
)

// printReportHeader identifies the build and platform, so certtest output posted to the RFC
// discussion carries the context needed to interpret it. Printed before any hardware call:
// a report from a machine where key creation fails is still a useful data point.
func printReportHeader() {
	fmt.Println("key-protecc certtest")
	fmt.Printf("  %-8s %s\n", "commit:", buildCommit())
	fmt.Printf("  %-8s %s %s/%s\n", "go:", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  %-8s %s\n", "os:", osVersion())
	fmt.Printf("  %-8s %s\n", "backend:", backendName)
}

func buildCommit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "+dirty"
	}
	return rev
}

func keyDescription(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	default:
		return fmt.Sprintf("%T", pub)
	}
}

func durationStats(ds []time.Duration) (median, min, max time.Duration) {
	sorted := slices.Clone(ds)
	slices.Sort(sorted)
	return sorted[len(sorted)/2], sorted[0], sorted[len(sorted)-1]
}

func fmtDuration(d time.Duration) string {
	return d.Round(10 * time.Microsecond).String()
}
