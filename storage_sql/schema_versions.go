package storage_sql

import (
	"database/sql"
)

func checkSchemaVersionsTable(tx *sql.Tx) error {
	_, err := tx.Exec(
		`CREATE TABLE IF NOT EXISTS schema_version (
			tablename TEXT PRIMARY KEY,
			version INTEGER NOT NULL
		)`)
	return err
}

func schemaTableExists(tx *sql.Tx, table string) bool {
	rows, err := tx.Query(`SELECT * FROM ` + table + ` LIMIT 1`)
	if nil != rows {
		rows.Close()
	}
	return nil == err
}

func schemaGetVersion(tx *sql.Tx, table string) (*int64, error) {
	if rows, err := tx.Query(
		`SELECT version
		FROM schema_version
		WHERE tablename = $1`, table); nil != err {
		return nil, err
	} else {
		defer rows.Close()
		if !rows.Next() {
			if schemaTableExists(tx, table) {
				var version int64 = -1
				// don't know the version, but it exists; return "-1" as version
				return &version, nil
			} else {
				// not found
				return nil, nil
			}
		}

		var version int64
		if err := rows.Scan(&version); nil != err {
			return nil, err
		}
		return &version, nil
	}
}

func schemaSetVersion(tx *sql.Tx, table string, version int64) error {
	_, err := tx.Exec(
		`INSERT OR REPLACE INTO schema_version
		(tablename, version) VALUES ($1, $2)`, table, version)
	return err
}
