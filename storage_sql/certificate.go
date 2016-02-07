package storage_sql

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	i "github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

// --------------------------------------------------------------------
// implementations for i.StorageCertificate
// --------------------------------------------------------------------

func (scert *sqlStorageCertificate) Storage() i.Storage {
	return scert.storage
}

func (scert *sqlStorageCertificate) StorageDirectory() i.StorageDirectory {
	return scert.registration.directory
}

func (scert *sqlStorageCertificate) Directory() *types.Directory {
	return scert.StorageDirectory().Directory()
}

func (scert *sqlStorageCertificate) StorageRegistration() i.StorageRegistration {
	return scert.registration
}

func (scert *sqlStorageCertificate) Certificate() *types.Certificate {
	return &scert.certificate
}

func (scert *sqlStorageCertificate) SetCertificate(certificate types.Certificate) error {
	if err := scert.storage.saveCertificate(scert.id, scert.registration.id, certificate); nil != err {
		return err
	}
	scert.certificate = certificate
	return nil
}

func (scert *sqlStorageCertificate) Delete() error {
	if _, err := scert.storage.db.Exec(`DELETE FROM certificate WHERE id = %1`, scert.id); nil != err {
		return err
	}
	scert.id = -1
	scert.certificate = types.Certificate{}
	return nil
}

// --------------------------------------------------------------------
// end [implementations for i.StorageCertificate]
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// implementations for i.StorageRegistration
// --------------------------------------------------------------------

func (sreg *sqlStorageRegistration) NewCertificate(cert types.Certificate) (i.StorageCertificate, error) {
	export, err := cert.Export(sreg.storage.lastPassword())
	if nil != err {
		return nil, err
	}

	name := &cert.Name
	if len(cert.Name) == 0 {
		name = nil
	}

	_, err = sreg.storage.db.Exec(
		`INSERT INTO certificate (registration_id, name, revoked, expires, location, linkIssuer, certificatePem, privateKeyPem) VALUES
			($1, $2, $3, $4, $5, $6, $7, $8)`,
		sreg.id, name, cert.Revoked, cert.Certificate.NotAfter, cert.Location,
		cert.LinkIssuer, export.CertificatePem, export.PrivateKeyPem)
	if nil != err {
		return nil, err
	}

	return sreg.LoadCertificate(cert.Location)
}

func (sreg *sqlStorageRegistration) CertificateInfos() ([]i.CertificateInfo, error) {
	rows, err := sreg.storage.db.Query(
		`SELECT name, revoked, location, linkIssuer, certificatePem
		FROM certificate
		WHERE registration_id = $1
			AND NOT revoked
			AND expires > CURRENT_TIMESTAMP
		ORDER BY id DESC
		`, sreg.id)
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	return certInfoListFromRows(rows)
}

func (sreg *sqlStorageRegistration) CertificateInfosAll() ([]i.CertificateInfo, error) {
	rows, err := sreg.storage.db.Query(
		`SELECT name, revoked, location, linkIssuer, certificatePem
		FROM certificate
		WHERE registration_id = $1
		ORDER BY id DESC
		`, sreg.id)
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	return certInfoListFromRows(rows)
}

func (sreg *sqlStorageRegistration) Certificates() ([]i.StorageCertificate, error) {
	if rows, err := sreg.storage.db.Query(
		`SELECT id, registration_id, name, revoked, location, linkIssuer, certificatePem, privateKeyPem
		FROM certificate
		WHERE registration_id = $1
			AND NOT revoked
			AND expires > CURRENT_TIMESTAMP
		ORDER BY id DESC
		`, sreg.id); nil != err {
		return nil, err
	} else {
		defer rows.Close()
		result := []i.StorageCertificate{}
		for {
			if scert, err := sreg.storage.loadCertificateFromSql(rows, sreg); nil != err {
				return nil, err
			} else if nil == scert {
				return result, nil
			} else {
				result = append(result, scert)
			}
		}
	}
}

func (sreg *sqlStorageRegistration) CertificatesAll() ([]i.StorageCertificate, error) {
	if rows, err := sreg.storage.db.Query(
		`SELECT id, registration_id, name, revoked, location, linkIssuer, certificatePem, privateKeyPem
		FROM certificate
		WHERE registration_id = $1
		ORDER BY id DESC
		`, sreg.id); nil != err {
		return nil, err
	} else {
		defer rows.Close()
		result := []i.StorageCertificate{}
		for {
			if scert, err := sreg.storage.loadCertificateFromSql(rows, sreg); nil != err {
				return nil, err
			} else if nil == scert {
				return result, nil
			} else {
				result = append(result, scert)
			}
		}
	}
}

func (sreg *sqlStorageRegistration) LoadCertificate(locationOrName string) (i.StorageCertificate, error) {
	if rows, err := sreg.storage.db.Query(
		`SELECT id, registration_id, name, revoked, location, linkIssuer, certificatePem, privateKeyPem
		FROM certificate
		WHERE registration_id = $1 AND (location = $2 OR name = $2)`, sreg.id, locationOrName); nil != err {
		return nil, err
	} else {
		defer rows.Close()
		if cert, err := sreg.storage.loadCertificateFromSql(rows, sreg); nil != err || nil == cert {
			// make sure to create a nil interface from the nil pointer!
			return nil, err
		} else {
			return cert, nil
		}
	}
}

// --------------------------------------------------------------------
// end [implementations for i.StorageRegistration]
// --------------------------------------------------------------------

type sqlStorageCertificate struct {
	storage      *sqlStorage
	registration *sqlStorageRegistration
	id           int64
	certificate  types.Certificate
}

func checkCertificateTable(tx *sql.Tx) error {
	if version, err := schemaGetVersion(tx, `certificate`); nil != err {
		return err
	} else if nil == version {
		if _, err := tx.Exec(
			`CREATE TABLE certificate (
				id INTEGER PRIMARY KEY,
				registration_id INT NOT NULL,
				name TEXT,
				revoked INT NOT NULL,
				expires TEXT NOT NULL,
				location TEXT NOT NULL,
				linkIssuer TEXT NOT NULL,
				certificatePem BLOB NOT NULL,
				privateKeyPem BLOB,
				FOREIGN KEY(registration_id) REFERENCES registration(id),
				UNIQUE (registration_id, location),
				CONSTRAINT certificate_unique_reg_name UNIQUE (registration_id, name)
			)`); nil != err {
			return err
		}
		if err := schemaSetVersion(tx, `certificate`, 1); nil != err {
			return err
		}
	} else {
		switch *version {
		case -1:
			// add name, expires and revoked
			if _, err := tx.Exec(
				`ALTER TABLE certificate ADD COLUMN name TEXT
				`); nil != err {
				return err
			}
			if _, err := tx.Exec(
				`CREATE UNIQUE INDEX certificate_unique_reg_name ON certificate (registration_id, name)
				`); nil != err {
				return err
			}
			if _, err := tx.Exec(
				`ALTER TABLE certificate ADD COLUMN expires TEXT NOT NULL DEFAULT ''
				`); nil != err {
				return err
			}
			if _, err := tx.Exec(
				`ALTER TABLE certificate ADD COLUMN revoked INT NOT NULL DEFAULT 0
				`); nil != err {
				return err
			}
			if err := schemaSetVersion(tx, `certificate`, 1); nil != err {
				return err
			}
			utils.Infof("Updating certificate table, assigning names")
			if rows, err := tx.Query(
				`SELECT id, certificatePem FROM certificate ORDER BY id DESC
			`); nil != err {
				return err
			} else {
				defer rows.Close()
				for rows.Next() {
					var id int64
					var certificatePem []byte
					if err := rows.Scan(&id, &certificatePem); nil != err {
						return err
					}
					certBlock, _ := pem.Decode(certificatePem)
					if certBlock.Type != "CERTIFICATE" {
						return fmt.Errorf("Couldn't decode certificate id %v: unexpected block type %#v", id, certBlock.Type)
					}
					if cert, err := x509.ParseCertificate(certBlock.Bytes); nil != err {
						utils.Debugf("Couldn't parse certificate id %v: %v", id, err)
						return fmt.Errorf("Couldn't parse certificate id %v: %v", id, err)
					} else {
						if _, err := tx.Exec(`UPDATE OR FAIL certificate SET expires = $1 WHERE id = $2`, cert.NotAfter, id); nil != err {
							return fmt.Errorf("Couldn't set expires for certificate id %d: %v", id, err)
						}

						name := cert.Subject.CommonName
						utils.Debugf("Trying to name certificate id %v %#v", id, name)
						if _, err := tx.Exec(`UPDATE OR FAIL certificate SET name = $1 WHERE id = $2`, name, id); nil != err {
							utils.Debugf("Couldn't name certificate %#v, name probably already in use; trying to append #%d: %v", name, id, err)
							// try appending #id to name
							name = fmt.Sprintf("%s#%d", name, id)
							if _, err := tx.Exec(`UPDATE OR FAIL  certificate SET name = $1 WHERE id = $2`, name, id); nil != err {
								return fmt.Errorf("Couldn't name certificate %#v or %#v: %v", cert.Subject.CommonName, name, err)
							}
						}
					}
				}
			}
			utils.Infof("Finished updating certificate table")
		case 1:
			// current version
		default:
			return fmt.Errorf("Unsupported schema_version %d for %s", version, `certificate`)
		}
	}
	return nil
}

func certInfoListFromRows(rows *sql.Rows) ([]i.CertificateInfo, error) {
	var certs []i.CertificateInfo
	for rows.Next() {
		var name, location, linkIssuer string
		var revoked bool
		var certificatePem []byte
		if err := rows.Scan(&name, &revoked, &location, &linkIssuer, &certificatePem); nil != err {
			return nil, err
		}

		info := i.CertificateInfo{
			Name:       name,
			Revoked:    revoked,
			Location:   location,
			LinkIssuer: linkIssuer,
		}

		// ignore errors in certificate
		certBlock, _ := pem.Decode(certificatePem)
		if certBlock.Type != "CERTIFICATE" {
			utils.Debugf("Couldn't decode certificate %v: unexpected block type %#v", location, certBlock.Type)
		} else if cert, err := x509.ParseCertificate(certBlock.Bytes); nil != err {
			utils.Debugf("Couldn't parse certificate %v: %v", location, err)
		} else {
			info.Certificate = cert
		}

		certs = append(certs, info)
	}
	return certs, nil
}

func (storage *sqlStorage) loadCertificateFromSql(rows *sql.Rows, sregHint *sqlStorageRegistration) (*sqlStorageCertificate, error) {
	if !rows.Next() {
		return nil, nil
	}

	var id, registration_id int64
	var name, location, linkIssuer string
	var revoked bool
	var certificatePem []byte
	var privateKeyPem sql.NullString
	if err := rows.Scan(&id, &registration_id, &name, &revoked, &location, &linkIssuer, &certificatePem, &privateKeyPem); nil != err {
		return nil, err
	}

	var privKeyPem []byte
	if privateKeyPem.Valid {
		privKeyPem = []byte(privateKeyPem.String)
	}

	cert := &sqlStorageCertificate{
		storage:      storage,
		registration: sregHint,
		id:           id,
	}

	if err := cert.certificate.Import(
		types.CertificateExport{
			Name:           name,
			Revoked:        revoked,
			CertificatePem: certificatePem,
			PrivateKeyPem:  privKeyPem,
			Location:       location,
			LinkIssuer:     linkIssuer,
		}, storage.passwordPrompt); nil != err {
		return nil, err
	}

	return cert, nil
}

func (storage *sqlStorage) saveCertificate(id int64, registration_id int64, cert types.Certificate) error {
	export, err := cert.Export(storage.lastPassword())
	if nil != err {
		return err
	}

	name := &cert.Name
	if len(cert.Name) == 0 {
		name = nil
	}

	_, err = storage.db.Exec(
		`UPDATE certificate SET
			registration_id = $1, name = $2, revoked = $3, expires = $4, location = $5, linkIssuer = $6, certificatePem = $7, privateKeyPem = $8
		WHERE id = $9`,
		registration_id, name, cert.Revoked, cert.Certificate.NotAfter,
		cert.Location, cert.LinkIssuer, export.CertificatePem,
		export.PrivateKeyPem, id)

	return err
}
