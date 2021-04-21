package dockerclient

import (
	"encoding/json"
	"os"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	logs "github.com/sirupsen/logrus"
)

type defaultKeychain struct{}

var DefaultKeychain authn.Keychain = &defaultKeychain{}

// Resolve implements Keychain.
func (dk *defaultKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	cf, err := config.Load(os.Getenv("DOCKER_CONFIG"))
	if err != nil {
		return nil, err
	}

	// See:
	// https://github.com/google/ko/issues/90
	// https://github.com/moby/moby/blob/fc01c2b481097a6057bec3cd1ab2d7b4488c50c4/registry/config.go#L397- L404
	key := target.RegistryStr()

	cfg, err := cf.GetAuthConfig(key)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(cfg)
	if err == nil {
		logs.Infof("defaultKeychain.Resolve(%q) = %s", key, string(b))
	} else {

		return nil, err
	}

	empty := types.AuthConfig{}
	if cfg == empty {
		return authn.Anonymous, nil

	}
	return authn.FromConfig(authn.AuthConfig{
		Username:      cfg.Username,
		Password:      cfg.Password,
		Auth:          cfg.Auth,
		IdentityToken: cfg.IdentityToken,
		RegistryToken: cfg.RegistryToken,
	}), nil
}

func NewBearerAuth(token string) authn.Authenticator {
	return &authn.Bearer{
		Token: token,
	}
}

func NewBasicAuth(u, p string) authn.Authenticator {
	return &authn.Basic{
		Username: u,
		Password: p,
	}
}
