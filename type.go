package auth

import "context"

type (
	ServiceAccount struct {
		Type                    string `json:"type,omitempty"`
		ProjectID               string `json:"project_id,omitempty"`
		PrivateKeyID            string `json:"private_key_id,omitempty"`
		PrivateKey              string `json:"private_key,omitempty"`
		ClientEmail             string `json:"client_email,omitempty"`
		ClientID                string `json:"client_id,omitempty"`
		AuthURI                 string `json:"auth_uri,omitempty"`
		TokenURI                string `json:"token_uri,omitempty"`
		AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url,omitempty"`
		ClientX509CertURL       string `json:"client_x509_cert_url,omitempty"`
	}
)

var serviceAccountCtxKey = "service account"

// WithServiceAccount returns copy parent context and associates it with ServiceAccount.
func WithServiceAccount(c context.Context, sa *ServiceAccount) context.Context {
	return context.WithValue(c, &serviceAccountCtxKey, sa)
}

func serviceAccountFrom(c context.Context) *ServiceAccount {
	if sa, ok := c.Value(&serviceAccountCtxKey).(*ServiceAccount); ok {
		return sa
	}
	return nil
}
