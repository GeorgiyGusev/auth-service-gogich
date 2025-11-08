package conns

import (
	"os"
	"strconv"

	"github.com/redis/go-redis/v9"
)

func NewRedisConn() (*redis.Client, error) {
	dbNum, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		return nil, err
	}

	return redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       dbNum,
	}), nil
}
