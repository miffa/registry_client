package dockerclient

import (
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

//////////////////////////////////////////////////
// TROption is a functional option for crane.
type TROption func(*TROptions)

// WithAuth is a functional option for overriding the default authenticator
// for remote operations.
//
// The default authenticator is authn.Anonymous.
func WithAuth(auth authn.Authenticator) TROption {
	return func(o *TROptions) {
		o.remote = append(o.remote, remote.WithAuth(auth))
	}
}

func WithAuthFromDocker() TROption {
	return func(o *TROptions) {
		o.remote = append(o.remote, remote.WithAuthFromKeychain(DefaultKeychain))
	}
}

// WithTransport is a functional option for overriding the default transport
// for remote operations.
func WithTransport(t http.RoundTripper) TROption {
	return func(o *TROptions) {
		o.remote = append(o.remote, remote.WithTransport(t))
	}
}

// WithInsecure is an Option that allows image references to be fetched without TLS.
func WithInsecure(fg bool) TROption {
	return func(o *TROptions) {
		if fg {
			o.name = append(o.name, name.Insecure)
		}
	}
}

////// WithStrictValidation
//// if true
// StrictValidation is an Option that requires image references to be fully
// specified; i.e. no defaulting for registry (dockerhub), repo (library),
// or tag (latest).
//// if  false
// WeakValidation is an Option that sets defaults when parsing names, see
// StrictValidation.
func WithStrictValidation(fg bool) TROption {
	return func(o *TROptions) {
		if fg {
			o.name = append(o.name, name.StrictValidation)
		} else {
			o.name = append(o.name, name.WeakValidation)
		}
	}
}

type TROptions struct {
	name   []name.Option
	remote []remote.Option
}

func makeTROptions(opts ...TROption) TROptions {
	opt := TROptions{}

	for _, o := range opts {
		o(&opt)
	}

	return opt
}
