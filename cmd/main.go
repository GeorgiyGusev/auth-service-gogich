package main

import (
	"log"
	"log/slog"
	"os"

	"github.com/KontoraMarketel/auth-service-gogich/internal"
	"github.com/KontoraMarketel/auth-service-gogich/internal/conns"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	slogfiber "github.com/samber/slog-fiber"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	l := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(l)

	app := fiber.New()
	app.Use(slogfiber.New(l))
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "*",
		AllowMethods: "*",
	}))

	postgres_conn, err := conns.NewConn()
	if err != nil {
		log.Fatal(err)
	}

	identityRepoImpl := internal.NewIdentityRepoImpl(postgres_conn)
	internal.NewHandler(identityRepoImpl).RegisterHandler(app)

	log.Fatal(app.Listen(":3000"))
}
