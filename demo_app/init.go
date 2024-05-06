package demo_app

import (
	"emperror.dev/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"ondc-buyer/demo_app/configs"
)

type LibraryOpts struct {
	env     string
	appName string
}

type LibraryArgsFunc func(opts *LibraryOpts)

func defaultLibraryOpts() LibraryOpts {
	return LibraryOpts{env: "none", appName: "none"}
}

func WithEnv(env string) LibraryArgsFunc {
	return func(opts *LibraryOpts) {
		opts.env = env
	}
}

func WithAppName(appName string) LibraryArgsFunc {
	return func(opts *LibraryOpts) {
		opts.appName = appName
	}
}

func InitCommonsLibrary(libraryArgs ...LibraryArgsFunc) {
	opts := defaultLibraryOpts()
	for _, argFunc := range libraryArgs {
		argFunc(&opts)
	}
	if opts.env == "none" {
		panic("env is not set")
	}
	configs.GlobalConfigs = readConfigs(opts)

	//database.NewConnector(configs.GlobalConfigs.Database)
}

func readConfigs(opts LibraryOpts) configs.Configuration {
	v, _ := viper.New(), pflag.NewFlagSet(opts.appName, pflag.ExitOnError)

	configs.Configure(v, opts.env)

	err := v.ReadInConfig()
	_, configFileNotFound := err.(viper.ConfigFileNotFoundError)
	if configFileNotFound {
		panic(errors.Wrap(err, "failed to read configuration"))
	}

	var config configs.Configuration
	err = v.Unmarshal(&config)
	if err != nil {
		panic(errors.Wrap(err, "failed to unmarshal configuration"))
	}

	err = config.Validate()
	if err != nil {
		panic(errors.WithMessage(err, "failed to validate configuration"))
	}
	return config
}
