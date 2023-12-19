package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slog"
	"golang.org/x/oauth2"

	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"

	goidc "github.com/coreos/go-oidc/v3/oidc"
)

var (
	callbackPath = "/callback"
	key          = []byte("test1234test1234")
)

func NewAuth() rp.RelyingParty {
	_err := godotenv.Load()
	if _err != nil {
		log.Fatal("Error loading .env file")
	}

	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	keyPath := os.Getenv("KEY_PATH")
	issuer := os.Getenv("ISSUER")
	// port := os.Getenv("PORT")
	scopes := strings.Split(os.Getenv("SCOPES"), " ")

	// redirectURI := fmt.Sprintf("http://localhost:%v%v", port, callbackPath)
	redirectURI := fmt.Sprintf("http://localhost:%v%v", 5173, callbackPath)
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)
	client := &http.Client{
		Timeout: time.Minute,
	}
	// enable outgoing request logging
	logging.EnableHTTPClient(client,
		logging.WithClientGroup("client"),
	)

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(client),
		rp.WithLogger(logger),
	}
	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	if keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(keyPath)))
	}

	// One can add a logger to the context,
	// pre-defining log attributes as required.
	ctx := logging.ToContext(context.TODO(), logger)

	provider, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}
	return provider
}

func NewOidc() (*goidc.Provider, oauth2.Config) {
	_err := godotenv.Load()
	if _err != nil {
		log.Fatal("Error loading .env file")
	}

	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	issuer := os.Getenv("ISSUER")
	// port := os.Getenv("PORT")
	// scopes := strings.Split(os.Getenv("SCOPES"), " ")

	redirectURI := fmt.Sprintf("http://localhost:%v%v", 5173, callbackPath)

	gidc, err := goidc.NewProvider(context.Background(), issuer)
	if err != nil {
		// handle error
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: gidc.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{goidc.ScopeOpenID, "profile", "email"},
	}

	return gidc, oauth2Config
}
