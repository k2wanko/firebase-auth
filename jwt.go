package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
)

const (
	// ClientCertURL is
	ClientCertURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

	// FirebaseAidienceURL is
	FirebaseAidienceURL = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
)

// SigningMethod is built-in AppEngine signing method
type SigningMethod struct{}

var (
	// BlackListedClaims is List of blacklisted claims which cannot be provided when creating a custom token
	// FYI: https://firebase.google.com/docs/auth/server/create-custom-tokens
	BlackListedClaims = []string{
		"acr", "amr", "at_hash", "aud", "auth_time", "azp",
		"cnf", "c_hash", "exp", "iat", "iss", "jti", "nbf", "nonce",
	}

	signingMethod = new(SigningMethod)
)

// Alg is algorithm name
func (s *SigningMethod) Alg() string {
	return "RS256"
}

// Sign is Implment SigningMethod#Sign
func (s *SigningMethod) Sign(signingString string, key interface{}) (string, error) {
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
func (s *SigningMethod) Verify(signingString, signature string, key interface{}) error {
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

	claims := &jwt.MapClaims{
		"uid":    uid,
		"iss":    sa,
		"sub":    sa,
		"aud":    FirebaseAidienceURL,
		"iat":    iat.Unix(),
		"exp":    exp.Unix(),
		"claims": developerClaims,
	}

	return jwt.NewWithClaims(signingMethod, claims).SignedString(c)
}

// VerifyIDToken is Verifies the format and signature of a Firebase Auth ID token
func VerifyIDToken(c context.Context, idToken string) (*jwt.Token, error) {
	return jwt.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		t.Method = signingMethod
		return c, nil
	})
}
