package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"go-auth/internal/auth"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)

	alowed := []string{"*"}
	// CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: alowed,
	}))

	// why map, becuase it similarly represents the JSON in Golang :)
	// claims := make(map[string]interface{})
	// json.Unmarshal(body, &claims)
	// return claims, nil

	// Security Headers
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("Strict-Transport-Security", "max-age=5184000; includeSubDomains")
			next.ServeHTTP(w, r)
		})
	})

	r.Use(middleware.Logger)

	r.Get("/", s.HelloWorldHandler)
	r.Get("/health", s.healthHandler)
	r.Get("/login", s.loginHandler)

	// r.Post("/verify", s.verifyHandler)

	r.Get("/auth", s.authHandler)

	r.Post("/verify", s.codeVerifyHandler)

	return r
}

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := make(map[string]string)
	resp["message"] = "Hello World"

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("error handling JSON marshal. Err: %v", err)
	}

	_, _ = w.Write(jsonResp)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	jsonResp, _ := json.Marshal(s.db.Health())
	_, _ = w.Write(jsonResp)
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	provider := auth.NewAuth()
	state := func() string {
		return uuid.New().String()
	}

	fmt.Println(state())

	authURL := rp.AuthURL(state(), provider)

	fmt.Println("AUN\n", authURL)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) authHandler(w http.ResponseWriter, r *http.Request) {
	_, oauth2Config := auth.NewOidc()

	state := func() string {
		return uuid.New().String()
	}

	fmt.Println(state())

	authURL := oauth2Config.AuthCodeURL(state())

	fmt.Println("AUN\n", authURL)

	http.Redirect(w, r, authURL, http.StatusFound)
}

type Message struct {
	Code string `json:"code"`
}

func (s *Server) verifyHandler(w http.ResponseWriter, r *http.Request) {
	var msg Message

	err := json.NewDecoder(r.Body).Decode(&msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	provider := auth.NewAuth()

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		data, err := json.Marshal(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}

	var params rp.URLParamOpt

	// params = msg.Code

	rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), provider, params)

	resp := make(map[string]string)

	resp["code"] = msg.Code

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("error handling JSON marshal. Err: %v", err)
	}

	// why map, becuase it similarly represents the JSON in Golang :)
	// claims := make(map[string]interface{})
	// json.Unmarshal(body, &claims)
	// return claims, nil

	_, _ = w.Write(jsonResp)
}

func (s *Server) codeVerifyHandler(w http.ResponseWriter, r *http.Request) {
	_, oauth2Config := auth.NewOidc()

	var msg Message

	err := json.NewDecoder(r.Body).Decode(&msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	oauth2Token, err := oauth2Config.Exchange(context.Background(), msg.Code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	// resp := make(map[string]string)

	// resp["code"] = msg.Code

	jsonResp, err := json.Marshal(oauth2Token)
	if err != nil {
		log.Fatalf("error handling JSON marshal. Err: %v", err)
	}

	// why map, becuase it similarly represents the JSON in Golang :)
	// claims := make(map[string]interface{})
	// json.Unmarshal(body, &claims)
	// return claims, nil

	_, _ = w.Write(jsonResp)
}

type Token struct {
	RefreshToken string `json:"refreshToken"`
}

func (s *Server) refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	_, oauth2Config := auth.NewOidc()

	var token Token

	err := json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_token := oauth2.Token{
		RefreshToken: token.RefreshToken,
	}

	tokenSource := oauth2Config.TokenSource(context.Background(), &_token)

	oauth2Token, err := tokenSource.Token()
	if err != nil {
		log.Fatal(err)
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	// resp := make(map[string]string)

	// resp["code"] = msg.Code

	fmt.Println("xxx", oauth2Token)

	jsonResp, err := json.Marshal(oauth2Token)
	if err != nil {
		log.Fatalf("error handling JSON marshal. Err: %v", err)
	}

	// why map, becuase it similarly represents the JSON in Golang :)
	// claims := make(map[string]interface{})
	// json.Unmarshal(body, &claims)
	// return claims, nil

	_, _ = w.Write(jsonResp)
}

func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	var token Token

	err := json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Perform token revocation
	err = revokeToken(token.RefreshToken)

	if err != nil {
		log.Fatal(err)
	}

	resp := make(map[string]string)

	resp["code"] = "Token successfully revoked"

	fmt.Println("Token successfully revoked")

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("error handling JSON marshal. Err: %v", err)
	}

	// why map, becuase it similarly represents the JSON in Golang :)
	// claims := make(map[string]interface{})
	// json.Unmarshal(body, &claims)
	// return claims, nil

	_, _ = w.Write(jsonResp)
}

func revokeToken(refreshToken string) error {
	_, oauth2Config := auth.NewOidc()

	issuer := os.Getenv("ISSUER")

	revokeEndpoint, err := url.JoinPath(issuer, "/oauth/v2/revoke")

	_token := oauth2.Token{
		RefreshToken: refreshToken,
	}

	// Create an HTTP client with the ability to revoke tokens
	httpClient := oauth2Config.Client(context.TODO(), &_token)

	if err != nil {
		return err
	}

	// Create a POST request to the revocation endpoint
	req, err := http.NewRequest("POST", revokeEndpoint, nil)
	if err != nil {
		return err
	}

	// Set the authentication header
	req.SetBasicAuth(oauth2Config.ClientID, oauth2Config.ClientSecret)

	// Set the form data with the token to be revoked
	req.Form = make(url.Values)
	req.Form.Set("token", refreshToken)

	// Perform the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation failed with status: %v", resp.Status)
	}

	return nil
}
