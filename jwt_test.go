//+build appengine

package auth

import (
	"os"
	"testing"

	"golang.org/x/net/context"

	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
)

var aeInstance aetest.Instance

func TestMain(m *testing.M) {
	var err error
	aeInstance, err = aetest.NewInstance(nil)
	if err != nil {
		panic(err)
	}

	code := m.Run()

	aeInstance.Close()
	os.Exit(code)
}

func newTestContext() context.Context {
	r, _ := aeInstance.NewRequest("GET", "/", nil)
	return appengine.NewContext(r)
}

func TestCreateCustomToken(t *testing.T) {
	t.Parallel()
	c := newTestContext()
	tok, err := CreateCustomToken(c, "some-id", map[string]interface{}{
		"premium_account": true,
	})

	if err != nil {
		t.Errorf("CreateCustomToken err = %v", err)
		if tok != "" {
			t.Errorf("Token was not empty; tok = %v", tok)
		}
		return
	}

	if tok == "" {
		t.Errorf("Token was empty")
	}

	t.Logf("tok = %s", tok)
}

func TestVerifyIDToken(t *testing.T) {
	t.Parallel()
	c := newTestContext()
	tokStr, err := CreateCustomToken(c, "some-id", map[string]interface{}{
		"premium_account": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := VerifyIDToken(c, tokStr)
	t.Logf("tokStr = %s", tokStr)
	if err != nil {
		t.Errorf("VerifyIDToken error: %v", err)
		return
	}

	if !tok.Valid {
		t.Errorf("token was not valid")
	}
}
