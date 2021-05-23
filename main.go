package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
)

const (
	certUrl string = "https://api.line.me/oauth2/v2.1/certs"
	issuer  string = "https://access.line.me"
)

// ErrWrongLineChannelID defines worng channel id.
var ErrWrongLineChannelID error = errors.New("channel id is not equal to the site")

var config struct {
	ChannelID string
	APISecret string
}

// Header defines jwt token header
type Header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// Payload defines decoded payload by id token.
type Payload struct {
	Amr         []string `json:"amr"`
	ChannelID   string   `json:"aud"`
	Email       string   `json:"email"`
	ExpiredAt   int64    `json:"exp"`
	GeneratedAt int64    `json:"iat"`
	Issuer      string   `json:"iss"`
	Name        string   `json:"name"`
	Picture     string   `json:"picture"`
	UserID      string   `json:"sub"`
}

// IDToken defines jwt token model.
type IDToken struct {
	Raw    string `json:"Raw"`
	Method struct {
		Name      string `json:"Name"`
		Hash      int    `json:"Hash"`
		KeySize   int    `json:"KeySize"`
		CurveBits int    `json:"CurveBits"`
	} `json:"Method"`
	Header    `json:"Header"`
	Payload   `json:"Claims"`
	Signature string `json:"Signature"`
	Valid     bool   `json:"Valid"`
}

func base64Decode(payload string) string {
	if rem := len(payload) % 4; rem > 0 {
		payload = payload + strings.Repeat("=", 4-rem)
	}

	return payload
}

func decodeHeader(headerBS64 string) (*Header, error) {
	header := base64Decode(headerBS64)
	bHeader, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, err
	}

	h := Header{}
	if err := json.Unmarshal(bHeader, &h); err != nil {
		return nil, errors.Wrapf(err, "json Unmarshal() failed, %s", string(bHeader))
	}

	return &h, nil
}

func fetchJSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certUrl, nil)
	if err != nil {
		return nil, errors.Wrap(err, "can't gen request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "can't fetch line oauth cert keys")
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed request, status: %d", resp.StatusCode)
	}

	var jsonWebKeySet jose.JSONWebKeySet
	if err = json.NewDecoder(resp.Body).Decode(&jsonWebKeySet); err != nil {
		return nil, err
	}

	return &jsonWebKeySet, err
}

func findKey(keySet *jose.JSONWebKeySet, keyID string) (*jose.JSONWebKey, error) {
	for _, key := range keySet.Key(keyID) {
		return &key, nil
	}

	return nil, errors.New("jwk not found")
}

// VerifyIDToken verify id token by using HS256 or ES256.
func VerifyIDToken(ctx context.Context, idToken string) (*Payload, error) {
	splitToken := strings.Split(idToken, ".")
	if len(splitToken) != 3 {
		return nil, errors.New("illegal id token len")
	}

	headerBS64 := splitToken[0]
	header, err := decodeHeader(headerBS64)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			return nil, errors.New("illegal id token alg")
		}
		switch header.Algorithm {
		case jwt.SigningMethodES256.Alg():
			keySet, err := fetchJSONWebKeySet(ctx)
			if err != nil {
				return nil, err
			}

			jwkKey, err := findKey(keySet, header.KeyID)
			if err != nil {
				return nil, err
			}

			if jwkKey == nil {
				return nil, errors.New("header must bring key id")
			}

			return jwkKey.Key, nil
		case jwt.SigningMethodHS256.Alg():
			return []byte(config.APISecret), nil
		}
		return nil, errors.New("illegal id token alg")
	})
	if err != nil {
		return nil, errors.Wrap(err, "can't parse id token by using es256 verify")
	}

	bs, err := json.Marshal(token)
	if err != nil {
		return nil, errors.Wrapf(err, "json.MarshalIndent() failed, %s", token.Raw)
	}

	var id IDToken
	if err := json.Unmarshal(bs, &id); err != nil {
		return nil, errors.Wrapf(err, "json.Unmarshal() to IDToken failed, %s", string(bs))
	}

	if !id.Valid {
		return nil, errors.New("id token is invalid")
	}

	if id.Issuer != issuer {
		return nil, errors.New("not be signed by line")
	}

	expiredAt := time.Unix(id.ExpiredAt, 0)
	if expiredAt.Before(time.Now()) {
		return nil, errors.New("id token is expired")
	}

	if id.Payload.ChannelID != config.ChannelID {
		return nil, ErrWrongLineChannelID
	}

	return &id.Payload, nil
}

func main() {
	// data from message api and line login.
	config.ChannelID = ""
	config.APISecret = ""

	idToken := ""

	verify, err := VerifyIDToken(context.TODO(), idToken)
	if err != nil {
		log.Panic(err)
	}

	log.Println(verify.UserID)
}
