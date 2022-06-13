package datastore

import (
	"database/sql"

	"github.com/pressly/goose"
)

func init() {
	RegisterMigration(20180831104300, "SSOEndpointFlag", func(txn *sql.Tx, conf *goose.DBConf) error {

		addTokenID := "ALTER TABLE cnsis ADD sso_allowed BOOLEAN NOT NULL DEFAULT FALSE"
		_, err := txn.Exec(addTokenID)
		if err != nil {
			return err
		}

		return nil
	})
}
