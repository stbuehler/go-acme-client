package storage_sql

import (
	"database/sql"
	"encoding/json"
	"time"
)

func timeFromSqlNullstring(sqlTime sql.NullString) (*time.Time, error) {
	if sqlTime.Valid {
		return timeFromSql(sqlTime.String)
	} else {
		return nil, nil
	}
}

func timeFromSql(sqlTime string) (*time.Time, error) {
	timeStamp := &time.Time{}
	if timeStampJson, err := json.Marshal(sqlTime); nil != err {
		return nil, err
	} else if err := json.Unmarshal(timeStampJson, timeStamp); nil != err {
		return nil, err
	}
	return timeStamp, nil
}
