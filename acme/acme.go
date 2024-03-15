package acme

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type CertMan struct {
	info       Info
	client     *lego.Client
	user       *cfUser
	errHandler func(error)

	certFilepath string
	keyFilepath  string

	// e.g., 30 days before expiration
	// after each refres, the next refresh will be scheduled
	refreshInterval time.Duration
}

// SetRefreshInterval can be used to set how much time before expiration for automatic updates to happen.
// e.g., 30 days before expiration
// after each refres, the next refresh will be scheduled
func (cm *CertMan) SetRefreshInterval(d time.Duration) {
	cm.refreshInterval = d
}

func (cm *CertMan) SetFilepaths(cert, key string) {
	cm.certFilepath = cert
	cm.keyFilepath = key
}

func (cm *CertMan) Refresh() error {
	cert, err := cm.refresh()
	if err != nil {
		return err
	}
	return writeResWithPath(cert, cm.keyFilepath, cm.certFilepath)
}

func (cm *CertMan) TimedRefresher(close <-chan struct{}) {
	if close == nil {
		cm.errHandler(errors.New("close channel is nil"))
		return
	}
	if cm.refreshInterval <= 24*time.Hour {
		cm.refreshInterval = 7 * time.Hour * 24
	}
	timer := time.NewTimer(cm.refreshInterval)

	for {
		timer.Reset(cm.refreshInterval)
		select {
		case <-timer.C:
			cert, err := cm.refresh()
			if err != nil {
				cm.errHandler(err)
				continue
			}
			err = writeResWithPath(cert, cm.keyFilepath, cm.certFilepath)
			if err != nil {
				cm.errHandler(err)
				continue
			}
		case <-close:
			return
		}
	}
}

func writeResWithPath(resource *certificate.Resource, keyFp, certFp string) error {
	var wKey, wCert io.Writer
	var err error
	if wKey, err = os.Create(keyFp); err != nil {
		return err
	}
	if wCert, err = os.Create(certFp); err != nil {
		return err
	}
	return WriteResources(resource, wKey, wCert)
}

func NewCertMan(info Info, handler func(error)) (*CertMan, error) {
	if info.PrivateKey == nil {
		return nil, errors.New("private key is nil")
	}
	if len(info.Domains) == 0 {
		return nil, errors.New("no domains provided")
	}
	if info.AuthEmail == "" {
		return nil, errors.New("no email provided")
	}
	if info.AuthKey == "" {
		return nil, errors.New("no auth key provided")
	}
	if handler == nil {
		handler = func(err error) {
			fmt.Println("error:", err)
		}
	}
	cm := &CertMan{
		info:       info,
		errHandler: handler,
		user: &cfUser{
			email: info.AuthEmail,
			key:   info.PrivateKey,
		},
	}
	err := cm.initClient()
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func (cm *CertMan) initClient() error {
	provider, err := getProvider(cm.info)
	if err != nil {
		return err
	}
	cm.client, err = getLegoClient(cm.user)
	if err != nil {
		return err
	}

	// These never return non-nil errors.
	_ = cm.client.Challenge.SetDNS01Provider(provider)
	_ = cm.client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "443"))

	reg, err := cm.client.Registration.ResolveAccountByKey()
	if err != nil {
		reg, err = cm.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
	}

	cm.user.registration = reg
	return nil
}

func (cm *CertMan) refresh() (cert *certificate.Resource, err error) {
	request := certificate.ObtainRequest{
		Domains: cm.info.Domains,
		Bundle:  true,
	}
	return cm.client.Certificate.Obtain(request)
}
