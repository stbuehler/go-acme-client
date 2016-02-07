package storage_sql

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	i "github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/ui"
)

// --------------------------------------------------------------------
// implementations for i.Storage
// --------------------------------------------------------------------

func (storage *sqlStorage) SetPassword(password string) {
	storage.passwordPrompt = func() (string, error) {
		return password, nil
	}
	storage.lastPassword = func() string {
		return password
	}
}

// in directory.go:
// func (storage *sqlStorage) LoadDirectory(rootURL string) (StorageDirectory, error)
// func (storage *sqlStorage) NewDirectory(directory types.Directory) (StorageDirectory, error)

// in registration.go:
// func (storage *sqlStorage) RegistrationList() (RegistrationList, error)
// func (storage *sqlStorage) LoadRegistration(name string) (StorageRegistration, error)

// --------------------------------------------------------------------
// end [implementations for i.Storage]
// --------------------------------------------------------------------

type sqlStorage struct {
	db             *sql.DB
	passwordPrompt func() (string, error)
	lastPassword   func() string
}

func OpenSQLite(UI ui.UserInterface, filename string) (i.Storage, error) {
	db, err := sql.Open("sqlite3", filename)
	if nil != err {
		return nil, err
	}
	return Open(UI, db)
}

func Open(UI ui.UserInterface, db *sql.DB) (i.Storage, error) {
	pwPrompt, lastPassword := UI.PasswordPromptOnce("Enter storage password")
	storage := &sqlStorage{
		db:             db,
		passwordPrompt: pwPrompt,
		lastPassword:   lastPassword,
	}
	if tx, err := storage.db.Begin(); nil != err {
		return nil, err
	} else if err := func() error {
		if err := checkSchemaVersionsTable(tx); nil != err {
			return err
		}
		if err := checkDirectoryTable(tx); nil != err {
			return err
		}
		if err := checkRegistrationTable(tx); nil != err {
			return err
		}
		if err := checkAuthorizationTable(tx); nil != err {
			return err
		}
		if err := checkCertificateTable(tx); nil != err {
			return err
		}
		return nil
	}(); nil != err {
		tx.Rollback()
		return nil, err
	} else if err := tx.Commit(); nil != err {
		return nil, err
	}

	return storage, nil
}
