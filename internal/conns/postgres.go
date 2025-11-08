package conns

import (
	"errors"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

func NewPostgresConn() (*sqlx.DB, error) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		return nil, errors.New("POSTGRES_DSN postgres dsn is blank")
	}

	db, err := sqlx.Connect("pgx", dsn)

	return db, err
}
