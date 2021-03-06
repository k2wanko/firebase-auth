package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context/ctxhttp"
	"google.golang.org/appengine"
	"google.golang.org/appengine/urlfetch"
)

const (
	// ClientCertURL is URL containing the public keys for the Google certs
	ClientCertURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

	// FirebaseAudienceURL is Audience to use for Firebase Auth Custom tokens
	FirebaseAudienceURL = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
)

type (
	// AppEngineSigningMethod is built-in AppEngine signing method
	AppEngineSigningMethod struct{}

	// FirebaseClaims is Token struct
	FirebaseClaims struct {
		UID           string      `json:"uid,omitempty"`
		UserIDStr     string      `json:"user_id,omitempty"`
		Email         string      `json:"email,omitempty"`
		EmailVerified bool        `json:"email_verified,omitempty"`
		Claims        interface{} `json:"claims,omitempty"`
		Firebase      *struct {
			SignInProvider string              `json:"sign_in_provider,omitempty"`
			Identities     map[string][]string `json:"identities,omitempty"`
		} `json:"firebase,omitempty"`

		*jwt.StandardClaims
	}

	certs map[string]*rsa.PublicKey
)

var (
	// BlackListedClaims is List of blacklisted claims which cannot be provided when creating a custom token
	// FYI: https://firebase.google.com/docs/auth/server/create-custom-tokens
	BlackListedClaims = []string{
		"acr", "amr", "at_hash", "aud", "auth_time", "azp",
		"cnf", "c_hash", "exp", "iat", "iss", "jti", "nbf", "nonce",
	}

	aeSigningMethod = new(AppEngineSigningMethod)
)

// Alg is algorithm name
func (s *AppEngineSigningMethod) Alg() string {
	return "RS256"
}

// Sign is Implment SigningMethod#Sign
func (s *AppEngineSigningMethod) Sign(signingString string, key interface{}) (string, error) {
	c, ok := key.(context.Context)
	if !ok {
		return "", jwt.ErrInvalidKey
	}

	_, sig, err := appengine.SignBytes(c, []byte(signingString))
	if err != nil {
		return "", err
	}
	return jwt.EncodeSegment(sig), nil
}

// Verify is Implment SigningMethod#Verify
func (s *AppEngineSigningMethod) Verify(signingString, signature string, key interface{}) error {
	c, ok := key.(context.Context)
	if !ok {
		return jwt.ErrInvalidKey
	}
	sig, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}
	certs, err := appengine.PublicCertificates(c)
	if err != nil {
		return err
	}

	haser := sha256.New()
	haser.Write([]byte(signingString))

	var certErr error
	for _, cert := range certs {
		key, err := jwt.ParseRSAPublicKeyFromPEM(cert.Data)
		if err != nil {
			return err
		}
		if certErr = rsa.VerifyPKCS1v15(key, crypto.SHA256, haser.Sum(nil), sig); certErr == nil {
			return nil
		}
	}

	return certErr
}

// UserID is Firebase UserID from Token
func (f *FirebaseClaims) UserID() string {
	if f.UID != "" {
		return f.UID
	}

	if f.UserIDStr != "" {
		return f.UserIDStr
	}

	return f.Subject
}

// CreateCustomToken is Creates a new Firebase Auth Custom token.
func CreateCustomToken(c context.Context, uid string, developerClaims interface{}) (string, error) {
	if uid == "" {
		return "", errors.New("uid is empty")
	}
	sa, err := appengine.ServiceAccount(c)
	if err != nil {
		return "", err
	}
	if sa == "" {
		sa = fmt.Sprintf("%s@appspot.gserviceaccount.com", appengine.AppID(c))
	}

	if developerClaims != nil {
		var dc map[string]interface{}
		switch c := developerClaims.(type) {
		case map[string]interface{}:
			dc = c
		default:
			// ToDo:
		}
		for _, key := range BlackListedClaims {
			if _, ok := dc[key]; ok {
				return "", fmt.Errorf("%s is reserved and cannot be specified", key)
			}
		}
	}

	iat := time.Now()
	exp := iat.Add(time.Hour)

	claims := &FirebaseClaims{
		UID:    uid,
		Claims: developerClaims,
		StandardClaims: &jwt.StandardClaims{
			Audience:  FirebaseAudienceURL,
			ExpiresAt: exp.Unix(),
			IssuedAt:  iat.Unix(),
			Issuer:    sa,
			Subject:   sa,
		},
	}

	certs, err := appengine.PublicCertificates(c)
	if err != nil {
		return "", err
	}

	for _, cert := range certs {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = cert.KeyName
		rawToken, err := token.SigningString()
		if err != nil {
			return "", err
		}

		keyName, sig, err := appengine.SignBytes(c, []byte(rawToken))
		if err != nil {
			return "", err
		}

		if keyName == cert.KeyName {
			return strings.Join([]string{rawToken, jwt.EncodeSegment(sig)}, "."), nil
		}
	}

	return "", errors.New("Not found key")
}

// VerifyIDToken is Verifies the format and signature of a Firebase Auth ID token
func VerifyIDToken(c context.Context, idToken string) (*jwt.Token, error) {
	if idToken == "" {
		return nil, errors.New("idToken is empty")
	}
	return jwt.ParseWithClaims(idToken, &FirebaseClaims{}, func(t *jwt.Token) (interface{}, error) {
		appID := appengine.AppID(c)
		if id := t.Header["aid"]; id == appID {
			t.Method = aeSigningMethod
			return c, nil
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, jwt.ErrInvalidKey
		}

		claims, _ := t.Claims.(*FirebaseClaims)
		if claims.StandardClaims.Audience != appID {
			return nil, errors.New("Invalid Token: aud")
		}

		iss := strings.Split(claims.StandardClaims.Issuer, "/")
		if appID != iss[len(iss)-1:][0] {
			return nil, errors.New("Invalid Token: iss")
		}

		if claims.StandardClaims.Subject == "" {
			return nil, errors.New("Invalid Token: sub")
		}

		if key, _ := keyCache.Get(c, kid); key != nil {
			return key, nil
		}

		crts, err := fetchPublicKeys(c)
		if err != nil {
			return nil, err
		}

		for id, key := range crts {
			if kid != id {
				continue
			}
			return key, nil
		}

		return nil, jwt.ErrInvalidKey
	})
}

func fetchPublicKeys(c context.Context) (certs, error) {
	hc := urlfetch.Client(c)
	resp, err := ctxhttp.Get(c, hc, ClientCertURL)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	t := make(map[string]string, 0)
	err = json.Unmarshal(b, &t)
	if err != nil {
		return nil, err
	}

	var exp time.Duration
	cacheControl := resp.Header.Get("cache-control")
	if cacheControl != "" {
		parts := strings.Split(cacheControl, ",")
		for _, part := range parts {
			subPars := strings.Split(strings.TrimSpace(part), "=")
			if subPars[0] != "max-age" {
				continue
			}
			maxAge, _ := strconv.ParseInt(subPars[1], 10, 64)
			exp = time.Duration(maxAge)
		}
	}

	crts := make(certs, len(t))
	for k, v := range t {
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(v))
		if err != nil {
			return nil, err
		}
		crts[k] = key
	}

	if exp != 0 {
		keyCache.Set(c, crts, exp)
	}

	return crts, nil
}
