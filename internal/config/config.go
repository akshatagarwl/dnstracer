package config

import (
	"github.com/caarlos0/env/v11"
)

type Config struct {
	UsePerfBuf bool   `env:"DNSTRACER_USE_PERFBUF" envDefault:"false"`
	Interface  string `env:"DNSTRACER_INTERFACE" envDefault:""`
}

func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
