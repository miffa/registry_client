package dockerclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	logs "github.com/sirupsen/logrus"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/validate"
	"github.com/pkg/errors"
)

// Tag applied to images that were pulled by digest. This denotes that the
// image was (probably) never tagged with this, but lets us avoid applying the
// ":latest" tag which might be misleading.
const (
	iWasADigestTag = "i-was-a-digest"
	ZeroStirng     = ""
)

type BasicAuthInfo struct {
	U string
	P string
}

type RegistryClient struct {
	certFile string
	tslconn  http.RoundTripper
	author   authn.Authenticator
	opts     *TROptions
}

func NewRegistryClientWithJwt(token string, cert string) (*RegistryClient, error) {
	r := &RegistryClient{certFile: cert}
	r.author = NewBearerAuth(token)

	rootCAs := x509.NewCertPool()
	if cert == "" {
		rootCAs = nil
	} else {
		certs, err := ioutil.ReadFile(r.certFile)
		if err != nil {
			logs.Errorf("Failed to append %q to RootCAs: %v", r.certFile, err)
			return nil, err
		}

		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			logs.Infof("No certs appended, using system certs only")
			return nil, err

		}
	}

	/*
		// LoadX509KeyPair reads files, so we give it the paths
		   clientCert, err := tls.LoadX509KeyPair("/path/to/client.crt", "/path/to/client.key")
		   tlsConfig := tls.Config{
		       RootCAs: pool,
		       Certificates: []tls.Certificate{clientCert},
		   }
	*/

	// Trust the augmented cert pool in our client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            rootCAs,
	}

	r.tslconn = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	r.set(WithInsecure(true),
		WithStrictValidation(true),
		//WithAuthFromDocker(),
		WithAuth(r.author),
		WithTransport(r.tslconn))

	return r, nil
}
func NewRegistryClient(u, p, cert string) (*RegistryClient, error) {
	r := &RegistryClient{certFile: cert}

	r.author = NewBasicAuth(u, p)

	rootCAs := x509.NewCertPool()
	if cert == "" {
		rootCAs = nil
	} else {
		certs, err := ioutil.ReadFile(r.certFile)
		if err != nil {
			logs.Errorf("Failed to append %q to RootCAs: %v", r.certFile, err)
			return nil, err
		}

		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			logs.Infof("No certs appended, using system certs only")
			return nil, err

		}
	}

	/*
		// LoadX509KeyPair reads files, so we give it the paths
		   clientCert, err := tls.LoadX509KeyPair("/path/to/client.crt", "/path/to/client.key")
		   tlsConfig := tls.Config{
		       RootCAs: pool,
		       Certificates: []tls.Certificate{clientCert},
		   }
	*/

	// Trust the augmented cert pool in our client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            rootCAs,
	}

	r.tslconn = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	r.set(WithInsecure(true),
		WithStrictValidation(true),
		//WithAuthFromDocker(),
		WithAuth(r.author),
		WithTransport(r.tslconn))

	return r, nil
}

func (r *RegistryClient) set(optlist ...TROption) {
	r.opts = &TROptions{}
	for _, o := range optlist {
		o(r.opts)
	}
}

// Push pushes the tarball img to a registry as dst.
//   push  de.tar 172.99.88.77/demo/debian latest
func (r *RegistryClient) Push(tarballfile string, desregistry string, tag string) error {
	var img v1.Image
	img, err := tarball.ImageFromPath(tarballfile, nil)
	if err != nil {
		return err
	}
	d, _ := img.Digest()
	s, _ := img.Size()
	logs.Infof("%s size:%d Digest:%s", tarballfile, s, d.String())

	if err := validate.Image(img); err != nil {
		return errors.WithMessage(err, "image format")
	}

	pushstring := desregistry + ":" + tag
	tagrepo, err := name.NewTag(pushstring, r.opts.name...)
	if err != nil {
		logs.Errorf("parsing tag %q: %v", pushstring, err)
		return err
	}
	return remote.Write(tagrepo, img, r.opts.remote...)
}

//   pull 172.99.88.77/demo/debian:latest debianc.tar
func (r *RegistryClient) Pull(srcrepo string, desttar string) error {
	ref, err := name.ParseReference(srcrepo, r.opts.name...)
	if err != nil {
		return fmt.Errorf("parsing tag %q: %v", srcrepo, err)
	}

	img, err := remote.Image(ref, r.opts.remote...)
	if err != nil {
		return nil
	}

	// WriteToFile wants a tag to write to the tarball, but we might have
	// been given a digest.
	// If the original ref was a tag, use that. Otherwise, if it was a
	// digest, tag the image with :i-was-a-digest instead.
	tag, ok := ref.(name.Tag)
	if !ok {
		d, ok := ref.(name.Digest)
		if !ok {
			return fmt.Errorf("ref wasn't a tag or digest")

		}
		tag = d.Repository.Tag(iWasADigestTag)
	}

	return tarball.WriteToFile(desttar, tag, img)
}

func (r *RegistryClient) Digest(srcrepo string) (string, error) {
	ref, err := name.ParseReference(srcrepo, r.opts.name...)
	if err != nil {
		return ZeroStirng, fmt.Errorf("parsing reference %q: %v", srcrepo, err)

	}
	desc, err := remote.Get(ref, r.opts.remote...)
	if err != nil {
		return ZeroStirng, err
	}

	return desc.Digest.String(), nil
}

func (r *RegistryClient) Ls(repostr string) ([]string, error) {
	repo, err := name.NewRepository(repostr, r.opts.name...)
	if err != nil {
		return nil, fmt.Errorf("parsing repo %q: %v", repo, err)

	}

	return remote.List(repo, r.opts.remote...)
}

func (r *RegistryClient) Catalog(registry string) ([]string, error) {
	reg, err := name.NewRegistry(registry, r.opts.name...)
	if err != nil {
		return nil, err

	}

	return remote.Catalog(context.TODO(), reg, r.opts.remote...)
}

func (r *RegistryClient) Mainfest(repostr string) (string, error) {
	ref, err := name.ParseReference(repostr, r.opts.name...)
	if err != nil {
		return ZeroStirng, fmt.Errorf("parsing reference %q: %v", repostr, err)

	}
	desc, err := remote.Get(ref, r.opts.remote...)
	if err != nil {
		return ZeroStirng, err

	}

	return string(desc.Manifest), nil
}
