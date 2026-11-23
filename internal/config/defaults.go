package config

import (
	"os"
	"time"
)

var (
	Version   = "0.1.0"
	Commit    = "unknown"
	BuildDate = "unknown"

	DefaultUserAgent = "WASP/" + Version + " (+https://github.com/caseypc/wasp; passive security audit)"
)

const (
	DefaultConcurrency      = 4
	DefaultTotalTimeout     = "30s"
	DefaultRequestTimeout   = "8s"
	DefaultMaxRequests      = 10
	DefaultMaxRedirects     = 3
	DefaultMaxResponseBytes = 1048576
	DefaultMinimumCoverage  = 0.8
	DefaultCertWarningDays  = 30
	DefaultTimeout          = 8 * time.Second
	DefaultTotalTimeoutSpan = 30 * time.Second

	LabelPass = "PASS"
	LabelFail = "FAIL"
)

func UserAgent() string {
	if value := os.Getenv("WASP_USER_AGENT"); value != "" {
		return value
	}
	return DefaultUserAgent
}

func PassLabel() string {
	if value := os.Getenv("WASP_LABEL_PASS"); value != "" {
		return value
	}
	return LabelPass
}

func FailLabel() string {
	if value := os.Getenv("WASP_LABEL_FAIL"); value != "" {
		return value
	}
	return LabelFail
}
