package config

import (
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"gorm.io/gorm/logger"
)

type userCommon struct {
	DB      database.Config `toml:"db"`
	Logging logger.Config   `toml:"logger"`
}
