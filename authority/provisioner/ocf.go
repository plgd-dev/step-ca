package provisioner

import (
	"context"
	"crypto/x509"

	stepProvisioner "github.com/smallstep/certificates/authority/provisioner"
)

const OCFPrefix = "ocf-"

type OCFSignOption struct{}

// OCF is the acme provisioner type, an entity that can authorize the OCF
// provisioning flow.
type OCF struct {
	provisioner stepProvisioner.Interface
}

func NewOCF(provisioner stepProvisioner.Interface) *OCF {
	return &OCF{provisioner}
}

// GetID returns the provisioner unique identifier.
func (p OCF) GetID() string {
	return p.provisioner.GetID()
}

// GetTokenID returns the identifier of the token.
func (p *OCF) GetTokenID(ott string) (string, error) {
	return p.provisioner.GetTokenID(ott)
}

// GetName returns the name of the provisioner.
func (p *OCF) GetName() string {
	return p.provisioner.GetName()
}

// GetType returns the type of provisioner.
func (p *OCF) GetType() stepProvisioner.Type {
	return p.provisioner.GetType()
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (p *OCF) GetEncryptedKey() (string, string, bool) {
	return p.provisioner.GetEncryptedKey()
}

// Init initializes and validates the fields of a JWK type.
func (p *OCF) Init(config stepProvisioner.Config) (err error) {
	return p.provisioner.Init(config)
}

// AuthorizeRevoke is not implemented yet for the OCF provisioner.
func (p *OCF) AuthorizeRevoke(token string) error {
	return p.provisioner.AuthorizeRevoke(token)
}

// AuthorizeSign validates the given token.
func (p *OCF) AuthorizeSign(ctx context.Context, v string) ([]stepProvisioner.SignOption, error) {
	opts, err := p.provisioner.AuthorizeSign(ctx, v)
	if err != nil {
		return nil, err
	}
	return append(opts, OCFSignOption{}), nil
}

// AuthorizeRenewal is not implemented for the OCF provisioner.
func (p *OCF) AuthorizeRenewal(cert *x509.Certificate) error {
	return p.provisioner.AuthorizeRenewal(cert)
}
