package gcp

import (
	"context"
	"encoding/gob"
	"fmt"
	"hash/fnv"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/txsvc/httpservice/pkg/api"
	"github.com/txsvc/stdlib/pkg/env"
	"github.com/txsvc/stdlib/storage"
)

const (
	GoogleOAuthStart    = "/_a/1/start"
	GoogleOAuthRedirect = "/_a/1/auth"
)

var (
	randState string
	config    *oauth2.Config
)

// OAuthStartEndpoint starts the OAuth 2.0 flow
func OAuthStartEndpoint(c echo.Context) error {

	// FIXME secure this by expecting the clientId as part of the request

	cfg := GetOAuthConfig()

	randState = fmt.Sprintf("st%d", time.Now().UnixNano())
	cfg.RedirectURL = fmt.Sprintf("%s%s", env.GetString("BASE_URL", "http://localhost:8080"), GoogleOAuthRedirect)
	authURL := cfg.AuthCodeURL(randState)
	config = &cfg

	// hand-over to Google for authentication
	return c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// OAuthRedirectEndpoint handles the OAuth call-back and creates a token on success
func OAuthRedirectEndpoint(c echo.Context) error {
	state := c.Request().FormValue("state")
	code := c.Request().FormValue("code")

	// FIXME handle cancellation !

	// FIXME validation !!

	fmt.Printf("%s -> %s\n", state, code)

	//ctx := appengine.NewContext(c.Request())
	ctx := c.Request().Context()
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return err
	}

	// store the token
	if err := storeToken(ctx, config, token); err != nil {
		return err
	}

	// clean-up
	randState = ""
	config = nil

	return api.StandardResponse(c, http.StatusOK, nil)
}

func NewOAuthClient(ctx context.Context, config *oauth2.Config) (*http.Client, error) {
	token, err := loadToken(ctx, config)
	if err != nil {
		return nil, err
	}

	return config.Client(ctx, token), nil
}

// https://www.googleapis.com/auth/spreadsheets.readonly
// https://www.googleapis.com/auth/devstorage.read_write

func GetOAuthConfig() oauth2.Config {
	return oauth2.Config{
		ClientID:     env.GetString("GOOGLE_CLIENT_ID", ""),
		ClientSecret: env.GetString("GOOGLE_CLIENT_SECRET", ""),
		Endpoint:     google.Endpoint,
		Scopes:       []string{
			//sheets.SpreadsheetsReadonlyScope,
			//storage.DevstorageReadWriteScope,
		},
	}
}

func storeToken(ctx context.Context, config *oauth2.Config, token *oauth2.Token) error {

	bkt := storage.Bucket(env.GetString("EXPORT_BUCKET", "gpte-open-export"))
	obj := bkt.Object(tokenLocation(config))

	writer, err := obj.NewWriter(ctx)
	if err != nil {
		return err
	}
	defer obj.Close()

	return gob.NewEncoder(writer).Encode(token)
}

func loadToken(ctx context.Context, config *oauth2.Config) (*oauth2.Token, error) {

	bkt := storage.Bucket(env.GetString("EXPORT_BUCKET", "gpte-open-export"))
	obj := bkt.Object(tokenLocation(config))

	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer obj.Close()

	t := new(oauth2.Token)
	err = gob.NewDecoder(reader).Decode(t)
	return t, err
}

func tokenLocation(config *oauth2.Config) string {
	hash := fnv.New32a()
	hash.Write([]byte(config.ClientID))
	hash.Write([]byte(config.ClientSecret))
	hash.Write([]byte(strings.Join(config.Scopes, " ")))

	return fmt.Sprintf("tok%v", hash.Sum32())
}
