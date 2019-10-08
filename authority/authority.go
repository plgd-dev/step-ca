package authority

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"

	"github.com/go-ocf/step-ca/authority/provisioner"

	"github.com/smallstep/certificates/authority"
	stepAuthority "github.com/smallstep/certificates/authority"
	stepProvisioner "github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/crypto/tlsutil"
	"golang.org/x/crypto/ssh"
)

const (
	legacyAuthority = "step-certificate-authority"
)

// Authority implements the Certificate Authority internal interface.
type Authority struct {
	config   *Config
	stepAuth *stepAuthority.Authority
}

type Option interface{}

// WrapperOption sets options to the Authority.
type WrapperOption func(*Authority)

// WithDatabase sets an already initialized authority database to a new
// authority. This option is intended to be use on graceful reloads.
func WithDatabase(db db.AuthDB) stepAuthority.Option {
	return stepAuthority.WithDatabase(db)
}

// New creates and initiates a new Authority type.
func New(config *Config, opts ...Option) (*Authority, error) {
	var stepOpts []stepAuthority.Option
	var wrapOpts []WrapperOption
	for _, o := range opts {
		switch v := o.(type) {
		case WrapperOption:
			wrapOpts = append(wrapOpts, v)
		case stepAuthority.Option:
			stepOpts = append(stepOpts, v)
		}
	}

	stepAuth, err := stepAuthority.New(config.Config, stepOpts...)
	if err != nil {
		return nil, err
	}

	return &Authority{
		config:   config,
		stepAuth: stepAuth,
	}, nil
}

// GetDatabase returns the authority database. If the configuration does not
// define a database, GetDatabase will return a db.SimpleDB instance.
func (a *Authority) GetDatabase() db.AuthDB {
	return a.stepAuth.GetDatabase()
}

// Shutdown safely shuts down any clients, databases, etc. held by the Authority.
func (a *Authority) Shutdown() error {
	return a.stepAuth.Shutdown()
}

func (a *Authority) Authorize(ctx context.Context, ott string) ([]stepProvisioner.SignOption, error) {
	return a.stepAuth.Authorize(ctx, ott)
}

func (a *Authority) AuthorizeSign(ott string) ([]stepProvisioner.SignOption, error) {
	return a.stepAuth.AuthorizeSign(ott)
}

func (a *Authority) GetTLSOptions() *tlsutil.TLSOptions {
	return a.stepAuth.GetTLSOptions()
}

func (a *Authority) Root(shasum string) (*x509.Certificate, error) {
	return a.stepAuth.Root(shasum)
}

func (a *Authority) Sign(cr *x509.CertificateRequest, opts stepProvisioner.Options, signOpts ...stepProvisioner.SignOption) (*x509.Certificate, *x509.Certificate, error) {
	return a.stepAuth.Sign(cr, opts, signOpts...)
}

func (a *Authority) Renew(peer *x509.Certificate) (*x509.Certificate, *x509.Certificate, error) {
	return a.stepAuth.Renew(peer)
}

func (a *Authority) LoadProvisionerByCertificate(c *x509.Certificate) (stepProvisioner.Interface, error) {
	p, err := a.stepAuth.LoadProvisionerByCertificate(c)
	if err != nil {
		return p, err
	}
	if strings.HasPrefix(strings.ToLower(p.GetName()), provisioner.OCFPrefix) {
		return provisioner.NewOCF(p), nil
	}
	return p, err
}

func (a *Authority) LoadProvisionerByID(ID string) (stepProvisioner.Interface, error) {
	p, err := a.stepAuth.LoadProvisionerByID(ID)
	if err != nil {
		return p, err
	}
	if strings.HasPrefix(strings.ToLower(p.GetName()), provisioner.OCFPrefix) {
		return provisioner.NewOCF(p), nil
	}
	return p, err
}

func (a *Authority) GetProvisioners(cursor string, limit int) (stepProvisioner.List, string, error) {
	list, v, err := a.stepAuth.GetProvisioners(cursor, limit)
	if err != nil {
		return list, v, err
	}
	res := make(stepProvisioner.List, 0, len(list))
	for _, p := range list {
		if strings.HasPrefix(strings.ToLower(p.GetName()), provisioner.OCFPrefix) {
			res = append(res, provisioner.NewOCF(p))
		} else {
			res = append(res, p)
		}
	}
	return res, v, err
}

func (a *Authority) Revoke(opts *authority.RevokeOptions) error {
	return a.stepAuth.Revoke(opts)
}

func (a *Authority) GetEncryptedKey(kid string) (string, error) {
	return a.stepAuth.GetEncryptedKey(kid)
}

func (a *Authority) GetRoots() (federation []*x509.Certificate, err error) {
	return a.stepAuth.GetRoots()
}

func (a *Authority) GetFederation() ([]*x509.Certificate, error) {
	return a.stepAuth.GetFederation()
}

func (a *Authority) GetTLSCertificate() (*tls.Certificate, error) {
	return a.stepAuth.GetTLSCertificate()
}

func (a *Authority) SignSSH(key ssh.PublicKey, opts stepProvisioner.SSHOptions, signOpts ...stepProvisioner.SignOption) (*ssh.Certificate, error) {
	return a.stepAuth.SignSSH(key, opts, signOpts)
}

func (a *Authority) GetRootCertificates() []*x509.Certificate {
	return a.stepAuth.GetRootCertificates()
}

func (a *Authority) SignSSHAddUser(key ssh.PublicKey, subject *ssh.Certificate) (*ssh.Certificate, error) {
	return a.stepAuth.SignSSHAddUser(key, subject)
}

func LoadConfiguration(filename string) (*Config, error) {
	config, err := stepAuthority.LoadConfiguration(filename)
	if err != nil {
		return nil, err
	}
	return &Config{
		Config: config,
	}, nil
}
