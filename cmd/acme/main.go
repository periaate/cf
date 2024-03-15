package main

import (
	"log"
	"os"
	"path/filepath"

	gf "github.com/jessevdk/go-flags"
	"github.com/periaate/cf/acme"
)

type options struct {
	TLSDir string `short:"t" long:"tlsdir" description:"Path to folder which contains the certificate and key files"`
}

func main() {
	opts := &options{}
	_, err := gf.Parse(opts)
	if err != nil {
		if gf.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalln("Error parsing flags:", err)
	}

	certfp := "./cert.pem"
	keyfp := "./key.pem"

	if len(opts.TLSDir) != 0 {
		if fi, err := os.Stat(opts.TLSDir); os.IsNotExist(err) {
			log.Fatalln("TLSDir does not exist")
		} else {
			if !fi.IsDir() {
				log.Fatalln("TLSDir is not a directory")
			}
		}
		certfp = filepath.Join(opts.TLSDir, "cert.pem")
		keyfp = filepath.Join(opts.TLSDir, "key.pem")
	}

	certFile, err := openOrCreateFile(certfp)
	if err != nil {
		log.Fatalln(err)
	}
	keyFile, err := openOrCreateFile(keyfp)
	if err != nil {
		log.Fatalln(err)
	}

	pk, err := acme.ReadPKey(keyFile)
	if err != nil {
		pk, err = acme.MakePKey(keyFile)
		if err != nil {
			log.Fatalln("error making new private key", err)
		}
	}

	res, err := acme.RefreshCerts(acme.Info{
		AuthEmail:  os.Getenv("CF_EMAIL"),
		AuthKey:    os.Getenv("CA_AUTH"),
		Domains:    []string{os.Getenv("CF_DOMAIN")},
		PrivateKey: pk,
	})

	if err != nil {
		log.Fatalln(err)
	}

	err = acme.WriteResources(res, keyFile, certFile)
	if err != nil {
		log.Fatalln("error writing resources to disk", err)
	}
}

func openOrCreateFile(fp string) (*os.File, error) {
	file, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}

	return file, nil
}
