package dockerclient

import (
	"fmt"
	"testing"
)

func TestHarbor(t *testing.T) {
	fmt.Printf("===\n")

	//imgfile := "/data/gopath/src/github.com/google/go-containerregistry/cmd/registry/debianc.tar"
	//localCertFile := "/etc/docker/certs.d/172.27.139.999/ca.crt"
	//repoadd := "docker.io/troilacloud/nginx"
	//repoadd := "docker.io/library/nginx"
	//repoadd := "quay.io/app-sre/nginx"
	repoadd := "quay.io/bitnami/tomcat"

	////////////////////////////

	//r, err := NewRegistryClient("k8scloud", "xxxxxx", "")
	r, err := NewRegistryClient("", "", "")
	if err != nil {
		t.Errorf("NewRegistryClient  err:%v", err)
		return
	}

	////////////////////////////////////
	//err = r.Push(imgfile, repoadd, "V1.002")
	//if err != nil {
	//	t.Errorf("push err:%v", err)
	//}
	//digest, err := r.Digest(repoadd + ":" + "V1.002")
	//tags, err := r.Ls(repoadd)
	//if err != nil {
	//	t.Errorf("Digest %s err:%v", repoadd, err)
	//}

	//fmt.Printf("%s push ok digest:%s\n", repoadd, digest)

	tags, err := r.Ls(repoadd)
	if err != nil {
		t.Errorf("Digest %s err:%v", repoadd, err)
	}

	for _, t := range tags {
		fmt.Printf("%s:%s\n", repoadd, t)
	}

	t.Logf("test ok")
}
