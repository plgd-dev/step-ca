package authority

import (
	"crypto/x509"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	stepProvisioner "github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/crypto/x509util"
)

func (a *Authority) OCFSign(csr *x509.CertificateRequest, signOpts stepProvisioner.Options, extraOpts ...stepProvisioner.SignOption) (*x509.Certificate, *x509.Certificate, error) {
	var (
		errContext     = apiCtx{"csr": csr, "signOptions": signOpts}
		certValidators = []provisioner.CertificateValidator{}
		issIdentity    = a.intermediateIdentity
		mods           = []x509util.WithOption{}
	)
	for _, op := range extraOpts {
		switch k := op.(type) {
		case provisioner.CertificateValidator:
			certValidators = append(certValidators, k)
		case provisioner.CertificateRequestValidator:
			if err := k.Valid(csr); err != nil {
				return nil, nil, &apiError{errors.Wrap(err, "sign"), http.StatusUnauthorized, errContext}
			}
		case provisioner.ProfileModifier:
			mods = append(mods, k.Option(signOpts))
		default:
			return nil, nil, &apiError{errors.Errorf("sign: invalid extra option type %T", k),
				http.StatusInternalServerError, errContext}
		}
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign: invalid certificate request"),
			http.StatusBadRequest, errContext}
	}

	leaf, err := x509util.NewLeafProfileWithCSR(csr, issIdentity.Crt, issIdentity.Key, mods...)
	if err != nil {
		return nil, nil, &apiError{errors.Wrapf(err, "sign"), http.StatusInternalServerError, errContext}
	}

	for _, v := range certValidators {
		if err := v.Valid(leaf.Subject()); err != nil {
			return nil, nil, &apiError{errors.Wrap(err, "sign"), http.StatusUnauthorized, errContext}
		}
	}

	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign: error creating new leaf certificate"),
			http.StatusInternalServerError, errContext}
	}

	serverCert, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign: error parsing new leaf certificate"),
			http.StatusInternalServerError, errContext}
	}

	caCert, err := x509.ParseCertificate(issIdentity.Crt.Raw)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign: error parsing intermediate certificate"),
			http.StatusInternalServerError, errContext}
	}

	if err = a.GetDatabase().StoreCertificate(serverCert); err != nil {
		if err != db.ErrNotImplemented {
			return nil, nil, &apiError{errors.Wrap(err, "sign: error storing certificate in db"),
				http.StatusInternalServerError, errContext}
		}
	}

	return serverCert, caCert, nil
}
