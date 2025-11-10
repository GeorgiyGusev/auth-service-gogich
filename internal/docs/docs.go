package docs

import (
	"embed"

	"github.com/gofiber/fiber/v2"
)

var specFS embed.FS

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Register(router fiber.Router) {
	docsGroup := router.Group("/docs")
	{
		docsGroup.Get("/openapi.yaml", h.serveSpec)
		docsGroup.Get("/", h.serveSwaggerUI)
	}
}

func (h *Handler) serveSpec(c *fiber.Ctx) error {
	return c.SendFile("openapi.yaml")
}

func (h *Handler) serveSwaggerUI(c *fiber.Ctx) error {
	html := `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Auth Service API</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3/swagger-ui.css">
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-bundle.js"></script>
        <script>
            SwaggerUIBundle({
                url: '/docs/openapi.yaml',
                dom_id: '#swagger-ui',
            });
        </script>
    </body>
    </html>`

	c.Set("Content-Type", "text/html")
	return c.SendString(html)
}
