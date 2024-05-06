package configs

import (
	"errors"
	"strings"

	"github.com/spf13/viper"
)

var GlobalConfigs Configuration

type Configuration struct {
	// App configuration
	App appConfig

	OndcConfigs ondcConfigs
}

type ondcConfigs struct {
	BuyerAppUrl                  string
	BuyerAppUri                  string
	GatewayUrl                   string
	SigningPrivateKey            string
	SigningPublicKey             string
	OndcEncryptionPublicKey      string
	PrivateKeyCrypto             string
	PublicKeyCrypto              string
	RegistryUrl                  string
	GstLegalEntityName           string
	GstBusinessAddress           string
	GstNo                        string
	EntityGstCityCode            string
	NameAsPerPan                 string
	PanNo                        string
	PanDateOfIncorporation       string
	NameOfAuthorisedSignatory    string
	AddressOfAuthorisedSignatory string
	EmailId                      string
	MobileNo                     string
	Country                      string
	SubscriberId                 string
	ValidFrom                    string
	ValidUntil                   string
	NetworkParticipantDomain     string
	NetworkParticipantType       string
	SubscribeUniqueId            string
	RequestId                    string
	CityList                     string
	LogoPath                     map[string]string
}

func (c Configuration) Validate() error {
	if err := c.App.Validate(); err != nil {
		return err
	}
	return nil
}

type appConfig struct {
	HttpAddr string
}

func (c appConfig) Validate() error {
	if c.HttpAddr == "" {
		return errors.New("http app server address is required")
	}

	return nil
}

func Configure(v *viper.Viper, env string) {
	// Viper settings

	v.AddConfigPath(".")
	v.SetConfigName(env + ".config")
	v.SetConfigType("yaml")

	// Environment variable settings
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()
}
