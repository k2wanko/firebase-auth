# Firebase Auth

[![GoDoc](https://godoc.org/github.com/k2wanko/firebase-auth?status.svg)](https://godoc.org/github.com/k2wanko/firebase-auth) [![Go Report Card](https://goreportcard.com/badge/github.com/k2wanko/firebase-auth)](https://goreportcard.com/report/github.com/k2wanko/firebase-auth)

Firebase Auth library

# Install

```bash
$ go get -v -u github.com/k2wanko/firebase-auth
```

# Usage

```go

import(
    ...
    'github.com/k2wanko/firebase-auth'
)

func handle(w http.ResponseWriter, r *http.Request) {
    ctx := appengine.NewContext(r)
    tokStr, err := auth.CreateCustomToken(ctx, "some-uid", map[string]interface{}{
        "premium_account": true,
    })
    if err != nil {
        panic(err)
    }

    tok, err := auth.VerifyIDToken(c, tokStr)
}
```