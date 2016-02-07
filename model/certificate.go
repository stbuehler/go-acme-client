package model

import (
	"encoding/pem"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

type CertificateModel interface {
	Refresh() error

	Certificate() types.Certificate

	SetName(name string) error
	SetRevoked(revoked bool) error
	SetPrivateKey(privateKey interface{}) error
}

type certificate struct {
	reg   *registration
	scert storage_interface.StorageCertificate
}

func (cert *certificate) Refresh() error {
	if certData, err := requests.FetchCertificate(cert.Certificate().Location); nil != err {
		return err
	} else {
		return cert.scert.SetCertificate(*certData)
	}
}

func (cert *certificate) Certificate() types.Certificate {
	return *cert.scert.Certificate()
}

func (cert *certificate) SetName(name string) error {
	data := cert.Certificate()
	if data.Name != name {
		data.Name = name
		return cert.scert.SetCertificate(data)
	} else {
		return nil
	}
}

func (cert *certificate) SetRevoked(revoked bool) error {
	data := cert.Certificate()
	if data.Revoked != revoked {
		data.Revoked = revoked
		return cert.scert.SetCertificate(data)
	} else {
		return nil
	}
}

func (cert *certificate) SetPrivateKey(privateKey interface{}) error {
	if nil == privateKey {
		certData := cert.scert.Certificate()
		certData.PrivateKey = nil
		cert.scert.SetCertificate(*certData)
		return nil
	} else if privKeyPem, err := utils.EncodePrivateKey(privateKey); nil != err {
		return err
	} else {
		certData := cert.scert.Certificate()
		certData.PrivateKey = privKeyPem
		cert.scert.SetCertificate(*certData)
		return nil
	}
}

func (reg *registration) importCertificate(certURL string, refresh bool) (*certificate, error) {
	if cert, err := reg.sreg.LoadCertificate(certURL); nil != err {
		return nil, err
	} else if nil != cert {
		certM := &certificate{reg: reg, scert: cert}
		if refresh {
			if err := certM.Refresh(); nil != err {
				return nil, err
			}
		}
		return certM, nil
	} else {
		if certData, err := requests.FetchCertificate(certURL); nil != err {
			return nil, err
		} else if cert, err := reg.sreg.NewCertificate(*certData); nil != err {
			return nil, err
		} else {
			return &certificate{reg: reg, scert: cert}, nil
		}
	}
}

func (reg *registration) CertificateInfos() ([]storage_interface.CertificateInfo, error) {
	return reg.sreg.CertificateInfos()
}

func (reg *registration) CertificateInfosAll() ([]storage_interface.CertificateInfo, error) {
	return reg.sreg.CertificateInfosAll()
}

func (reg *registration) Certificates() ([]CertificateModel, error) {
	if scerts, err := reg.sreg.Certificates(); nil != err {
		return nil, err
	} else {
		certs := make([]CertificateModel, len(scerts))
		for ndx, scert := range scerts {
			certs[ndx] = &certificate{
				reg:   reg,
				scert: scert,
			}
		}
		return certs, nil
	}
}

func (reg *registration) CertificatesAll() ([]CertificateModel, error) {
	if scerts, err := reg.sreg.CertificatesAll(); nil != err {
		return nil, err
	} else {
		certs := make([]CertificateModel, len(scerts))
		for ndx, scert := range scerts {
			certs[ndx] = &certificate{
				reg:   reg,
				scert: scert,
			}
		}
		return certs, nil
	}
}

func (reg *registration) LoadCertificate(locationOrName string) (CertificateModel, error) {
	if cert, err := reg.sreg.LoadCertificate(locationOrName); nil != err {
		return nil, err
	} else if nil != cert {
		return &certificate{reg: reg, scert: cert}, nil
	} else {
		return nil, nil
	}
}

func (reg *registration) FetchAllCertificates(updateAll bool) error {
	certUrls, err := requests.FetchCertificates(reg.sreg.Registration().Resource.CertificatesURL)
	if nil != err {
		return err
	}

	for _, certURL := range certUrls {
		if _, err := reg.ImportCertificate(certURL, updateAll); nil != err {
			return err
		}
	}
	return nil
}

func (reg *registration) ImportCertificate(certURL string, refresh bool) (CertificateModel, error) {
	if certM, err := reg.importCertificate(certURL, refresh); nil != err || nil == certM {
		// make sure to create a nil interface from the nil pointer!
		return nil, err
	} else {
		return certM, nil
	}
}

func (reg *registration) NewCertificate(name string, csr pem.Block) (CertificateModel, error) {
	if certData, err := requests.NewCertificate(reg.sreg.Directory(), reg.sreg.Registration().SigningKey, csr); nil != err {
		return nil, err
	} else {
		certData.Name = name
		if cert, err := reg.sreg.NewCertificate(*certData); nil != err {
			return nil, err
		} else {
			return &certificate{reg: reg, scert: cert}, nil
		}
	}
}
