package authority

import (
	"crypto/x509"
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

const ocfPrefix = "ocf."

func isValidError(err error) error {
	if err == nil {
		return nil
	}
	// SAN attribute is ignored- it is not used by OCF Identity certificates.
	if strings.Contains(err.Error(), "certificate request does not contain the valid DNS names") {
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
	cert.DNSNames = nil
	cert.EmailAddresses = nil
	cert.IPAddresses = nil
	cert.URIs = nil
	cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	cert.UnknownExtKeyUsage = []asn1.ObjectIdentifier{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44924, 1, 6}}

	return nil
}

type stepProvisionerASN1 struct {
	Type          int
	Name          []byte
	CredentialID  []byte
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

func (a *Authority) isOCF(signOpts []stepProvisioner.SignOption) bool {
	stepOIDProvisioner := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}
	var isOCF bool
	for _, o := range signOpts {
		var tmp stepProvisioner.Options
		if v, ok := o.(stepProvisioner.ProfileModifier); ok {
			withOption := v.Option(tmp)
			p, err := x509util.NewSelfSignedLeafProfile("test")
			if err != nil {
				continue
			}
			withOption(p)
			for _, ext := range p.Subject().ExtraExtensions {
				fmt.Printf("Authority.isOCF ext.Id=%+v\n", ext.Id)
				if reflect.DeepEqual(ext.Id, stepOIDProvisioner) {
					var val stepProvisionerASN1
					_, err := asn1.Unmarshal(ext.Value, &val)
					if err != nil {
						continue
					}
					fmt.Printf("Authority.isOCF val.Name=%+v\n", val.Name)
					if strings.HasPrefix(strings.ToLower(string(val.Name)), ocfPrefix) {
						isOCF = true
					}
				}
			}
		}
	}
	fmt.Printf("Authority.isOCF len(signOpts)=%v %v\n", signOpts, isOCF)
	return isOCF
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
		return nil, nil, &apiError{errors.Wrap(err, "ocfsign"), http.StatusUnauthorized, errContext}
	}

	for _, op := range extraOpts {
		switch k := op.(type) {
		case provisioner.CertificateValidator:
			certValidators = append(certValidators, k)
		case provisioner.CertificateRequestValidator:
			if err := k.Valid(csr); isValidError(err) != nil {
				return nil, nil, &apiError{errors.Wrap(err, "ocfsign"), http.StatusUnauthorized, errContext}
			}
		case provisioner.ProfileModifier:
			mods = append(mods, k.Option(signOpts))
		default:
			return nil, nil, &apiError{errors.Errorf("ocfsign: invalid extra option type %T", k),
				http.StatusInternalServerError, errContext}
		}
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "ocfsign: invalid certificate request"),
			http.StatusBadRequest, errContext}
	}

	leaf, err := x509util.NewLeafProfileWithCSR(csr, issIdentity.Crt, issIdentity.Key, mods...)
	if err != nil {
		return nil, nil, &apiError{errors.Wrapf(err, "ocfsign"), http.StatusInternalServerError, errContext}
	}

	for _, v := range certValidators {
		if err := v.Valid(leaf.Subject()); err != nil {
			return nil, nil, &apiError{errors.Wrap(err, "ocfsign"), http.StatusUnauthorized, errContext}
		}
	}

	if err := cleanUpCert(leaf.Subject()); err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "ocfsign: cannot clean up OCF Cert"),
			http.StatusInternalServerError, errContext}
	}

	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "ocfsign: error creating new leaf certificate"),
			http.StatusInternalServerError, errContext}
	}

	serverCert, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "ocfsign: error parsing new leaf certificate"),
			http.StatusInternalServerError, errContext}
	}

	caCert, err := x509.ParseCertificate(issIdentity.Crt.Raw)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "ocfsign: error parsing intermediate certificate"),
			http.StatusInternalServerError, errContext}
	}

	if err = a.GetDatabase().StoreCertificate(serverCert); err != nil {
		if err != db.ErrNotImplemented {
			return nil, nil, &apiError{errors.Wrap(err, "ocfsign: error storing certificate in db"),
				http.StatusInternalServerError, errContext}
		}
	}

	return serverCert, caCert, nil
}
