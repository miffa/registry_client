package main

import (
	"flag"

	"registryclient/dockerclient"

	"github.com/sirupsen/logrus"
)

var (
	filetar  *string = flag.String("tar", "", "image tarball file path") // xxxx/image.tar
	filetag  *string = flag.String("tag", "", "镜像tag")                   //  V1.00
	repo     *string = flag.String("repo", "", "镜像仓库")                   // docker.io/nginx/nginx
	certfile *string = flag.String("ca", "", "证书文件路径, 非必选(不填，使用http)")
	user     *string = flag.String("u", "anonymous", "user")
	paswd    *string = flag.String("p", "", "password")
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
	r, err := dockerclient.NewRegistryClient(*user, *paswd, *certfile)
	if err != nil {
		logrus.Errorf("NewRegistryClient  err:%v", err)
		return
	}

	err = r.Push(*filetar, *repo, *filetag)
	if err != nil {
		logrus.Errorf("push tarball file err;%v", err)
		return
	}
	//tags, err := r.Ls(repo)
	//if err != nil {
	//	logrus.Errorf("get tag list err;%v", err)
	//	return
	//}
	digest, err := r.Digest(*repo + ":" + *filetag)
	if err != nil {
		logrus.Errorf("get Digest err;%v", err)
		return
	}

	logrus.Infof("%s push ok digest:%s\n", *repo+":"+*filetag, digest)

}
