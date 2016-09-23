package auth

import (
	"crypto/rsa"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/memcache"
)

type cacheStore struct {
	prefix string
}

var keyCache = &cacheStore{"key"}

func (c *cacheStore) Set(ctx context.Context, crts certs, exp time.Duration) error {
	if len(crts) > 0 {
		return nil
	}

	items := make([]*memcache.Item, len(crts))
	for kid, key := range crts {
		items = append(items, &memcache.Item{
			Key:        c.prefix + kid,
			Object:     key,
			Expiration: exp,
		})
	}
	return memcache.Gob.SetMulti(ctx, items)
}

func (c *cacheStore) Get(ctx context.Context, key string) (*rsa.PublicKey, error) {
	item, err := memcache.Gob.Get(ctx, c.prefix+key, &rsa.PublicKey{})
	if err != nil {
		return nil, err
	}
	return item.Object.(*rsa.PublicKey), nil
}
