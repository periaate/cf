package cfacme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

type cfUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *cfUser) GetEmail() string                        { return u.email }
func (u *cfUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
func (u *cfUser) GetRegistration() *registration.Resource { return u.registration }

type Info struct {
	// Email to use for ACME registration
	AuthEmail string
	// Cloudflare API credentials
	AuthKey    string
	Domains    []string
	PrivateKey crypto.PrivateKey
}

func getProvider(info Info) (*cloudflare.DNSProvider, error) {
	providerCfg := cloudflare.NewDefaultConfig()
	providerCfg.AuthKey = info.AuthKey
	providerCfg.AuthEmail = info.AuthEmail
	provider, err := cloudflare.NewDNSProviderConfig(providerCfg)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

func getLegoClient(user registration.User) (*lego.Client, error) {
	clientCfg := lego.NewConfig(user)
	clientCfg.CADirURL = lego.LEDirectoryProduction
	clientCfg.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create new ACME client: %w", err)
	}
	return client, nil
}

// RefreshCerts attempts to obtain a new certificate for the given domains using the given info.
func RefreshCerts(info Info) (*certificate.Resource, error) {
	user := cfUser{
		email: info.AuthEmail,
		key:   info.PrivateKey,
	}

	client, err := getLegoClient(&user)
	if err != nil {
		return nil, err
	}

	provider, err := getProvider(info)
	if err != nil {
		return nil, err
	}

	// These never return non-nil errors.
	_ = client.Challenge.SetDNS01Provider(provider)
	_ = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "443"))

	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, err
		}
	}

	user.registration = reg

	request := certificate.ObtainRequest{
		Domains: info.Domains,
		Bundle:  true,
	}

	return client.Certificate.Obtain(request)
}

// WriteResources writes the certificate and private key to the given writers.
func WriteResources(resource *certificate.Resource, wKey, wCert io.Writer) error {
	n, err := wCert.Write(resource.Certificate)
	if err != nil {
		return err
	}
	if n != len(resource.Certificate) {
		return errors.New("failed to write certificate")
	}

	n, err = wKey.Write(resource.PrivateKey)
	if err != nil {
		return err
	}
	if n != len(resource.PrivateKey) {
		return errors.New("failed to write private key")
	}
	return nil
}

// ReadPKey reads a PEM-encoded private key from the given reader.
func ReadPKey(r io.Reader) (crypto.PrivateKey, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	p, rest := pem.Decode(b)
	if p == nil {
		return nil, errors.New("no pem block found in file")
	}
	if len(rest) > 0 {
		return nil, errors.New("extra data found in file")
	}

	return x509.ParsePKCS1PrivateKey(p.Bytes)
}

// MakePKey makes a new ECDSA private key and writes it to the given writer.
func MakePKey(w io.Writer) (crypto.PrivateKey, error) {
	newPK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	b, err := x509.MarshalECPrivateKey(newPK)
	if err != nil {
		return nil, err
	}

	err = pem.Encode(w, &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: b})
	if err != nil {
		return nil, err
	}

	return newPK, nil
}
