package settings

import (
	"os"
	"strconv"
	"time"
)

// Modes:
// - 0 production,
// - 1 local (no attestation)
var Mode int
var LogLevel string

func init() {
	if m, err := strconv.Atoi(os.Getenv("MODE")); err == nil {
		Mode = m
	} else {
		Mode = 1
	}
	if logLevelEnv := os.Getenv("LOG_LEVEL"); len(logLevelEnv) != 0 {
		LogLevel = logLevelEnv
	} else {
		LogLevel = "FATAL"
	}
}

const EncodingVersion = "1.0.0"

// Processor configuration
var QueuedActionsSleepTime = 100 * time.Millisecond

const ProxyTimeout = 2 * time.Second

const (
	MaxInstructionSize = 100 * 1024  // 100 KB
	MaxActionSize      = 1024 * 1024 // 1 MB
)

const GoogleCertLoc = "assets/google_confidential_space_root.crt"

const (
	ExtensionServerPort = 8888
	ExtensionPort       = 8889
)

const (
	ConfigureServerPort = 5500

	SetProxyURLEndpoint = "/proxy"
	ProxyURLEnvVar      = "PROXY_URL"

	SetInitialOwnerEndpoint = "/initial-owner"
	InitialOwnerEnvVar      = "INITIAL_OWNER"

	SetExtensionIDEndpoint = "/extension-id"
	ExtensionIDEnvVar      = "EXTENSION_ID"
)
