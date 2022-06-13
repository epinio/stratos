package datastore

import (
	"database/sql"

	"github.com/pressly/goose"
)

func init() {
	RegisterMigration(20180907123000, "SSOSetupFlag", func(txn *sql.Tx, conf *goose.DBConf) error {

		addTokenID := "ALTER TABLE console_config ADD use_sso BOOLEAN NOT NULL DEFAULT FALSE"
		_, err := txn.Exec(addTokenID)
		if err != nil {
			return err
		}

		return nil
	})
}
