module github.com/epinio/ui-backend/src/jetstream

go 1.16

require (
	bitbucket.org/liamstask/goose v0.0.0-20150115234039-8488cc47d90c
	github.com/antonlindstrom/pgstore v0.0.0-20170604072116-a407030ba6d0
	github.com/cf-stratos/mysqlstore v0.0.0-20170822100912-304308519d13
	github.com/go-sql-driver/mysql v1.5.0
	github.com/golang/mock v1.4.4
	github.com/gopherjs/gopherjs v0.0.0-20190411002643-bd77b112433e // indirect
	github.com/gorilla/context v1.1.1
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.1.3
	github.com/gorilla/websocket v1.4.2
	github.com/kat-co/vala v0.0.0-20170210184112-42e1d8b61f12
	github.com/kylelemons/go-gypsy v1.0.0 // indirect
	github.com/labstack/echo/v4 v4.6.0
	github.com/lib/pq v1.10.4 // indirect
	github.com/mattn/go-sqlite3 v1.14.5
	github.com/nwmac/sqlitestore v0.0.0-20180824125213-7d2ab221fb3f
	github.com/pkg/errors v0.8.1 // indirect
	github.com/satori/go.uuid v1.2.1-0.20181016170032-d91630c85102
	github.com/sirupsen/logrus v1.4.2
	github.com/smartystreets/assertions v0.0.0-20190401211740-f487f9de1cd3 // indirect
	github.com/smartystreets/goconvey v1.6.4
	github.com/stretchr/testify v1.5.1 // indirect
	github.com/ziutek/mymysql v1.5.4 // indirect
	golang.org/x/crypto v0.0.0-20220131195533-30dcbda58838
	gopkg.in/DATA-DOG/go-sqlmock.v1 v1.5.0
	gopkg.in/yaml.v2 v2.4.0
)

replace gopkg.in/DATA-DOG/go-sqlmock.v1 => github.com/DATA-DOG/go-sqlmock v1.1.3
