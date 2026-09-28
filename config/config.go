package config

import (
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	configFilePath = "config/auth-service.yaml"
)

type Secret struct {
	SignToken string `yaml:"sign_token"`
}

func (s Secret) String() string {
	return "******"
}

type AuthServiceConfig struct {
	Port   int    `yaml:"port"`
	Secret Secret `yaml:"secret"`
}

var (
	cfg  *AuthServiceConfig
	once sync.Once
)

func MustInitConfig() error {
	var err error
	once.Do(func() {
		var data []byte
		data, err = os.ReadFile(configFilePath)
		if err != nil {
			panic(err)
		}

		tempCfg := &AuthServiceConfig{}
		err = yaml.Unmarshal(data, tempCfg)
		if err != nil {
			panic(err)
		}
		cfg = tempCfg
	})
	return err
}
func Get() *AuthServiceConfig {
	return cfg
}
