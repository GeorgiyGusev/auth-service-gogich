package clients

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

const (
	signEndpoint = "/sign/jwt"
	jwksEndpoint = "/.well-known/jwks.json"
)

type CryptoServiceClient struct {
	baseURL string
	client  *http.Client
	jwks    *keyfunc.JWKS
}

func NewCryptoServiceClient() (*CryptoServiceClient, error) {
	cryptoServiceBaseUrl := os.Getenv("CRYPTO_SERVICE_URL")

	jwks, err := keyfunc.Get(fmt.Sprintf("%s%s", cryptoServiceBaseUrl, jwksEndpoint), keyfunc.Options{
		RefreshInterval: 6 * time.Hour,
		RefreshErrorHandler: func(err error) {
			fmt.Println("JWKS refresh error:", err.Error())
		},
		RefreshTimeout:    6 * time.Second,
		RefreshUnknownKID: true,
	})
	if err != nil {
		return nil, err
	}

	return &CryptoServiceClient{
		baseURL: cryptoServiceBaseUrl,
		client:  &http.Client{},
		jwks:    jwks,
	}, nil
}

func (c *CryptoServiceClient) Sign(payload interface{}) (string, error) {
	payloadReq := struct {
		Payload interface{} `json:"payload"`
	}{payload}

	body, err := json.Marshal(payloadReq)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+signEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	//if c.token != "" {
	//	req.Header.Set("Authorization", "Bearer "+c.token)
	//}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("service returned error: %s", string(data))
	}

	var respData struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return respData.Token, nil
}

func (c *CryptoServiceClient) Verify(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, c.jwks.Keyfunc)
	if err != nil {
		return nil, err
	}

	return token, nil

}
