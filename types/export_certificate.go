package types

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/stbuehler/go-acme-client/utils"
)

type CertificateExport struct {
	Name           string
	Revoked        bool
	CertificatePem []byte
	PrivateKeyPem  []byte
	Location       string
	LinkIssuer     string
}

func (cert *Certificate) Import(export CertificateExport, prompt PasswordPrompt) error {
	certificateBlock, err := importPem(export.CertificatePem, prompt, pemTypeCertificate)
	if nil != err {
		return err
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if nil != err {
		return err
	}
	var privateKeyBlock *pem.Block
	if nil != export.PrivateKeyPem {
		privateKeyBlock, err = importPem(export.PrivateKeyPem, prompt, pemTypeEcPrivateKey, pemTypeRsaPrivateKey)
		if nil != err {
			return err
		}
	}

	cert.Name = export.Name
	cert.Revoked = export.Revoked
	cert.Certificate = certificate
	cert.PrivateKey = privateKeyBlock
	cert.Location = export.Location
	cert.LinkIssuer = export.LinkIssuer

	return nil
}

func (cert Certificate) Export(password string) (*CertificateExport, error) {
	var privateKeyBlob []byte
	if nil != cert.PrivateKey {
		privateKeyBlock := *cert.PrivateKey
		if err := utils.EncryptPemBlock(&privateKeyBlock, password, utils.PemDefaultCipher); nil != err {
			return nil, err
		}
		privateKeyBlob = pem.EncodeToMemory(&privateKeyBlock)
	}

	return &CertificateExport{
		Name:           cert.Name,
		Revoked:        cert.Revoked,
		CertificatePem: pem.EncodeToMemory(utils.CertificateToPem(cert.Certificate)),
		PrivateKeyPem:  privateKeyBlob,
		Location:       cert.Location,
		LinkIssuer:     cert.LinkIssuer,
	}, nil
}
