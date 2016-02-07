package command_certificate

import (
	// "crypto"
	"crypto/x509"
	"fmt"
	"github.com/stbuehler/go-acme-client/requests"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
	"golang.org/x/crypto/ocsp"
)

type OCSPStatus int

const (
	Good    OCSPStatus = ocsp.Good
	Revoked OCSPStatus = ocsp.Revoked
	Unknown OCSPStatus = ocsp.Unknown
)

func (ocspStatus OCSPStatus) String() string {
	switch ocspStatus {
	case Good:
		return "Good"
	case Revoked:
		return "Revoked"
	case Unknown:
		return "Unknown"
	default:
		return fmt.Sprintf("Invalid status %d", int(ocspStatus))
	}
}

type RevocationReason int

const (
	Unspecified          RevocationReason = ocsp.Unspecified
	KeyCompromise        RevocationReason = ocsp.KeyCompromise
	CACompromise         RevocationReason = ocsp.CACompromise
	AffiliationChanged   RevocationReason = ocsp.AffiliationChanged
	Superseded           RevocationReason = ocsp.Superseded
	CessationOfOperation RevocationReason = ocsp.CessationOfOperation
	CertificateHold      RevocationReason = ocsp.CertificateHold
	RemoveFromCRL        RevocationReason = ocsp.RemoveFromCRL
	PrivilegeWithdrawn   RevocationReason = ocsp.PrivilegeWithdrawn
	AACompromise         RevocationReason = ocsp.AACompromise
)

func (revocationReason RevocationReason) String() string {
	switch revocationReason {
	case Unspecified:
		return "Unspecified"
	case KeyCompromise:
		return "KeyCompromise"
	case CACompromise:
		return "CACompromise"
	case AffiliationChanged:
		return "AffiliationChanged"
	case Superseded:
		return "Superseded"
	case CessationOfOperation:
		return "CessationOfOperation"
	case CertificateHold:
		return "CertificateHold"
	case RemoveFromCRL:
		return "RemoveFromCRL"
	case PrivilegeWithdrawn:
		return "PrivilegeWithdrawn"
	case AACompromise:
		return "AACompromise"
	default:
		return fmt.Sprintf("Invalid revocation reason %d", int(revocationReason))
	}
}

type SignatureAlgorithm x509.SignatureAlgorithm

func (sigAlg SignatureAlgorithm) String() string {
	return SignatureAlgorithmString(x509.SignatureAlgorithm(sigAlg))
}

func SignatureAlgorithmString(sigAlg x509.SignatureAlgorithm) string {
	switch sigAlg {
	case x509.UnknownSignatureAlgorithm:
		return "UnknownSignatureAlgorithm"
	case x509.MD2WithRSA:
		return "MD2WithRSA"
	case x509.MD5WithRSA:
		return "MD5WithRSA"
	case x509.SHA1WithRSA:
		return "SHA1WithRSA"
	case x509.SHA256WithRSA:
		return "SHA256WithRSA"
	case x509.SHA384WithRSA:
		return "SHA384WithRSA"
	case x509.SHA512WithRSA:
		return "SHA512WithRSA"
	case x509.DSAWithSHA1:
		return "DSAWithSHA1"
	case x509.DSAWithSHA256:
		return "DSAWithSHA256"
	case x509.ECDSAWithSHA1:
		return "ECDSAWithSHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSAWithSHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSAWithSHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSAWithSHA512"
	default:
		return fmt.Sprintf("Invalid signature algorithm %d", int(sigAlg))
	}
}

func CheckOCSP(cert types.Certificate) (OCSPStatus, error) {
	if 0 == len(cert.LinkIssuer) {
		return Unknown, fmt.Errorf("Unknown issuer certificate")
	}

	if 0 == len(cert.Certificate.OCSPServer) || 0 == len(cert.Certificate.OCSPServer[0]) {
		return Unknown, fmt.Errorf("No OCSP server defined")
	}

	issuerCert, err := requests.FetchCertificate(cert.LinkIssuer)
	if nil != err {
		return Unknown, fmt.Errorf("Failed to fetch issuer certificate: %v", err)
	}

	/*
		It seems the letsencrypt CA doesn't respond well to anything apart from SHA1

		var ocspReqOptions ocsp.RequestOptions
		switch cert.Certificate.SignatureAlgorithm {
		case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
			ocspReqOptions.Hash = crypto.SHA1
		case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
			ocspReqOptions.Hash = crypto.SHA256
		case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
			ocspReqOptions.Hash = crypto.SHA384
		case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
			ocspReqOptions.Hash = crypto.SHA512
		default:
			ocspReqOptions.Hash = crypto.SHA1
		}
	*/

	ocspReq, err := ocsp.CreateRequest(cert.Certificate, issuerCert.Certificate, nil)
	if nil != err {
		return Unknown, fmt.Errorf("Failed to create OCSP request: %v", err)
	}

	httpReq := utils.HttpRequest{
		Method: "POST",
		URL:    cert.Certificate.OCSPServer[0],
		Body:   ocspReq,
		Headers: utils.HttpRequestHeader{
			ContentType: "application/ocsp-request",
		},
	}

	resp, err := httpReq.Run()
	if nil != err {
		return Unknown, fmt.Errorf("OCSP HTTP request failed: %v", err)
	}

	if resp.ContentType != "application/ocsp-response" {
		return Unknown, fmt.Errorf("Invalid OCSP HTTP response Content-Type %#v", resp.ContentType)
	}

	ocspResp, err := ocsp.ParseResponse(resp.Body, issuerCert.Certificate)
	if nil != err {
		return Unknown, fmt.Errorf("Failed to parse OCSP response: %v", err)
	}

	utils.Debugf("OCSP response: { Status = %s, SerialNumber = 0x%x, ProducedAt = %s, ThisUpdate = %s, NextUpdate = %s, RevokedAt = %s, RevocationReason = %s, SignatureAlgorithm = %s }",
		OCSPStatus(ocspResp.Status), ocspResp.SerialNumber,
		ocspResp.ProducedAt, ocspResp.ThisUpdate, ocspResp.NextUpdate,
		ocspResp.RevokedAt, RevocationReason(ocspResp.RevocationReason),
		SignatureAlgorithm(ocspResp.SignatureAlgorithm))

	return OCSPStatus(ocspResp.Status), nil
}
