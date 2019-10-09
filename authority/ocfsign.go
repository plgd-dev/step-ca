package authority

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/google/uuid"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	stepProvisioner "github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/crypto/x509util"
)

func isValidError(err error) error {
	// SAN attribute is ignored- it is not used by OCF Identity certificates.
	if strings.HasPrefix(err.Error(), "certificate request does not contain the valid DNS names") {
		return nil
	}
	return err
}

func validateCSR(csr *x509.CertificateRequest) error {
	cn := strings.ToLower(csr.Subject.CommonName)
	if !strings.HasPrefix(cn, "uuid:") {
		return fmt.Errorf("invalid common name %v of Identity device OCF CSR", csr.Subject.CommonName)
	}
	deviceDesc := strings.Split(cn, ":")
	if len(deviceDesc) != 2 {
		return fmt.Errorf("invalid common name %v number of elements separated by ':' of Identity device OCF CSR", csr.Subject.CommonName)
	}
	_, err := uuid.Parse(deviceDesc[1])
	if err != nil {
		return fmt.Errorf("invalid common name %v UUID of Identity device OCF CSR", csr.Subject.CommonName)
	}
	return nil
}

func cleanUpCert(cert *x509.Certificate) error {
	eku := asn1.ObjectIdentifier{2, 5, 29, 37}
	cert.DNSNames = nil
	cert.EmailAddresses = nil
	cert.IPAddresses = nil
	cert.URIs = nil
	cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	ekuVal, err := asn1.Marshal([]asn1.ObjectIdentifier{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44924, 1, 6}})
	if err != nil {
		return err
	}
	var ekuReplaced bool
	for i := 0; i < len(cert.Extensions); i++ {
		if reflect.DeepEqual(cert.Extensions[i].Id, eku) {
			cert.Extensions[i].Value = ekuVal
			ekuReplaced = true
		}
	}
	for i := 0; i < len(cert.ExtraExtensions); i++ {
		if reflect.DeepEqual(cert.ExtraExtensions[i].Id, eku) {
			cert.ExtraExtensions[i].Value = ekuVal
			ekuReplaced = true
		}
	}
	if !ekuReplaced {
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    eku,
			Value: ekuVal,
		})
	}
	return nil
}

func (a *Authority) OCFSign(csr *x509.CertificateRequest, signOpts stepProvisioner.Options, extraOpts ...stepProvisioner.SignOption) (*x509.Certificate, *x509.Certificate, error) {
	var (
		errContext     = apiCtx{"csr": csr, "signOptions": signOpts}
		certValidators = []provisioner.CertificateValidator{}
		issIdentity    = a.intermediateIdentity
		mods           = []x509util.WithOption{}
	)

	err := validateCSR(csr)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign"), http.StatusUnauthorized, errContext}
	}

	for _, op := range extraOpts {
		switch k := op.(type) {
		case provisioner.CertificateValidator:
			certValidators = append(certValidators, k)
		case provisioner.CertificateRequestValidator:
			if err := k.Valid(csr); isValidError(err) != nil {
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

	if err := cleanUpCert(leaf.Subject()); err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign: cannot clean up OCF Cert"),
			http.StatusInternalServerError, errContext}
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
