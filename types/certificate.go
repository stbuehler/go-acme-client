package types

import (
	"crypto/x509"
	"encoding/pem"
)

type Certificate struct {
	Name        string
	Revoked     bool
	Certificate *x509.Certificate
	PrivateKey  *pem.Block
	Location    string
	LinkIssuer  string
}
