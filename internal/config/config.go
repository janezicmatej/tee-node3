package config

import (
	"fmt"
	"os"

	"github.com/naoina/toml"
	"gorm.io/gorm/logger"
)

type NodeConfig struct {
	Logging logger.Config `toml:"logger"`
	Server  ServerConfig  `toml:"server"`
}

type ServerConfig struct {
	Port   int `toml:"port"`
	WSPort int `toml:"ws_port"`
}

var DefaultServerConfig = ServerConfig{
	Port:   8545,
	WSPort: 50040,
}

// ReadConfigs reads user and system configurations from userFilePath and systemDirectoryPath.
//
// System configurations are read for Chain and protocolID set in the user configurations.
func ReadConfig(filePath string) (*NodeConfig, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading file %s with: %s", filePath, err)
	}

	config := NodeConfig{
		Server: DefaultServerConfig,
	}
	err = toml.Unmarshal(file, &config)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling file %s with: %s", filePath, err)
	}

	return &config, nil
}

// Hardcoded configuration for operations and subcommands
var InstructionOperations = map[string][]string{
	"REG": {
		"AVAILABILITY_CHECK",
		"TO_PAUSE_FOR_UPGRADE",
		"REPLICATE_FROM",
	},
	"WALLET": {
		"KEY_GENERATE",
		"KEY_DELETE",
		"KEY_MACHINE_BACKUP",
		"KEY_MACHINE_RESTORE",
		"KEY_MACHINE_BACKUP_REMOVE",
		"KEY_CUSTODIAN_BACKUP",
		"KEY_CUSTODIAN_RESTORE",
	},
	"XRP": {
		"PAY",
		"REISSUE",
	},
	"BTC": {
		"PAY",
		"REISSUE",
	},
	"FDC": {
		"PROVE",
	},
}

type ServiceMethod struct {
	Service string
	Method  string
}

var ServiceMethodMapping = map[string]map[string]ServiceMethod{
	"REG": {
		"AVAILABILITY_CHECK":   {"RegistryService", "CheckAvailability"},
		"TO_PAUSE_FOR_UPGRADE": {"RegistryService", "PauseForUpgrade"},
		"REPLICATE_FROM":       {"RegistryService", "ReplicateData"},
	},
	"WALLET": {
		"KEY_GENERATE":              {"WalletService", "GenerateKey"},
		"KEY_DELETE":                {"WalletService", "DeleteKey"},
		"KEY_MACHINE_BACKUP":        {"WalletService", "BackupMachineKey"},
		"KEY_MACHINE_RESTORE":       {"WalletService", "RestoreMachineKey"},
		"KEY_MACHINE_BACKUP_REMOVE": {"WalletService", "RemoveMachineBackup"},
		"KEY_CUSTODIAN_BACKUP":      {"CustodianService", "BackupCustodianKey"},
		"KEY_CUSTODIAN_RESTORE":     {"CustodianService", "RestoreCustodianKey"},
	},
	"XRP": {
		"PAY":     {"PaymentService", "ProcessXRPPayment"},
		"REISSUE": {"PaymentService", "ReissueXRP"},
	},
	"BTC": {
		"PAY":     {"PaymentService", "ProcessBTCPayment"},
		"REISSUE": {"PaymentService", "ReissueBTC"},
	},
	"FDC": {
		"PROVE": {"FDCService", "ProveOwnership"},
	},
}
