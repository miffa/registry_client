package main

import (
        "crypto/tls"
        "crypto/x509"
        "encoding/json"
        "flag"
        "io/ioutil"
        "net/http"
        "os"

        "github.com/docker/cli/cli/config"
        "github.com/docker/cli/cli/config/types"
        "github.com/google/go-containerregistry/pkg/authn"
        "github.com/google/go-containerregistry/pkg/name"
        v1 "github.com/google/go-containerregistry/pkg/v1"
        "github.com/google/go-containerregistry/pkg/v1/remote"
        ts "github.com/google/go-containerregistry/pkg/v1/remote/transport"
        "github.com/google/go-containerregistry/pkg/v1/tarball"
        "github.com/sirupsen/logrus"
)

var (
        filetar  *string = flag.String("tar", "", "image tarball file path")
        filetag  *string = flag.String("tag", "", "镜像tag")
        certfile *string = flag.String("ca", "", "证书文件路径, 非必选(不填，使用http)")
        user     *string = flag.String("u", "admin", "user")
        paswd    *string = flag.String("p", "Harbor12345", "password")
)

func main() {
        flag.Parse()
        if *filetar == "" {
                logrus.Errorf("empty image tarball file")
                return
        }
        if *filetag == "" {
                logrus.Errorf("empty image tar")
                return
        }

        DockerPushWithoutTLS()
}

func DockerPushWithoutTLS() {
        logrus.SetLevel(logrus.DebugLevel)
        var img v1.Image
        img, err := tarball.ImageFromPath(*filetar, nil)
        if err != nil {
                logrus.Errorf("ImageFromPath %s  err:%v", filetar, err)
                return
        }

        cf, err := img.ConfigName()
        if err != nil {
                logrus.Errorf(" ConfigName err :%v", err)
                return
        }
        d, err := img.Digest()
        if err != nil {
                logrus.Errorf(" Digest err :%v", err)
                return
        }

        mf, _ := img.Manifest()

        mainf, _ := json.Marshal(mf)

        s, _ := img.Size()
        logrus.Infof("%s info:", *filetar)
        logrus.Infof("size:%d", s)
        logrus.Infof("Digest :%s", d.String())
        logrus.Infof("ImageID:%s", cf.String())
        logrus.Infof("manifest:%s", string(mainf))

        /////////////////////////////////////////////////////////

        //rootCAs, _ := x509.SystemCertPool()
        //if rootCAs == nil {
        rootCAs := x509.NewCertPool()
        //}

        if *certfile == "" {
                rootCAs = nil
        } else {
                // Read in the cert file
                certs, err := ioutil.ReadFile(*certfile)
                if err != nil {
                        logrus.Errorf("Failed to append %q to RootCAs: %v", certfile, err)
                        return
                }

                // Append our cert to the system pool
                if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
                        logrus.Errorf("No certs appended, using system certs only")
                        return
                }
        }
        // Trust the augmented cert pool in our client
        tlsConfig := &tls.Config{
                InsecureSkipVerify: true,
                RootCAs:            rootCAs,
        }

        transport := http.Transport{
                TLSClientConfig: tlsConfig,
        }

        basicauth := NewBasicAuth(*user, *paswd)
        err = Push(img, *filetag,
                WithInsecure(true),
                WithStrictValidation(true),
                //WithAuthFromDocker(),
                WithAuth(basicauth),
                WithTransport(&transport))
        if err != nil {
                logrus.Errorf("push %s to %s err:%v", *filetar, *filetag, err)
                return
        }
        logrus.Infof("push %s to %s success", *filetar, *filetag)
        return

}

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

///////////////////////////////////////////////////////////
// Push pushes the v1.Image img to a registry as dst.
func Push(img v1.Image, dst string, opt ...TROption) error {
        o := makeTROptions(opt...)
        tag, err := name.NewTag(dst, o.name...)
        if err != nil {
                logrus.Errorf("parsing tag %q: %v", dst, err)
                return err
        }
        return remote.Write(tag, img, o.remote...)
}

////////////////////////////////////////////////////////////////////////
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
        // https://github.com/moby/moby/blob/fc01c2b481097a6057bec3cd1ab2d7b4488c50c4/registry/config.go#L397-L404
        key := target.RegistryStr()

        cfg, err := cf.GetAuthConfig(key)
        if err != nil {
                return nil, err
        }
        b, err := json.Marshal(cfg)
        if err == nil {
                logrus.Infof("defaultKeychain.Resolve(%q) = %s", key, string(b))
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

////////////////// http.RountTrip
func NewTroilaTransport(repo name.Registry,
        auth authn.Authenticator,
        t http.RoundTripper,
        scopes []string) (http.RoundTripper, error) {
        //
        return ts.New(repo, auth, t, scopes)
}
