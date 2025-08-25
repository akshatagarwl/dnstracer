package config

import (
	"github.com/caarlos0/env/v11"
)

type Config struct {
	UsePerfBuf bool   `env:"DNSTRACER_USE_PERFBUF" envDefault:"false"`
	Interface  string `env:"DNSTRACER_INTERFACE" envDefault:""`
}

const defaultInterface = "eth0"

func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	if cfg.Interface == "" {
		cfg.Interface = defaultInterface
	}
	return cfg, nil
}
