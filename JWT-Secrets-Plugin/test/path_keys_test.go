package josejwt_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"

	"github.com/fatih/structs"
	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/vault/logical"
	jwt "github.com/wenisman/vault_jwt_plugin/JWT-Secrets-Plugin/plugin"
)

func TestCRUDKey(t *testing.T) {
	b, storage := getTestBackend(t)

	/***  TEST SET OPERATION ***/
	startTime := time.Now()
	entry := jwt.KeyStorageEntry{
		Name:       "test-key",
		Algorithm:  crypto.SigningMethodHS256.Name,
		PrivateKey: "test-key",
	}
	resp, err := createKeyFromEntry(b, storage, t, entry)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	fmt.Printf("'Test create key' took %s\n", time.Since(startTime))

	/***  TEST GET OPERATION ***/
	startTime = time.Now()

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("keys/%s", entry.Name),
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	var returnedKey jwt.KeyStorageEntry
	err = mapstructure.Decode(resp.Data, &returnedKey)

	if returnedKey.Name != entry.Name {
		t.Fatalf("incorrect key name returned, not the same as saved value")
	} else if returnedKey.Algorithm != entry.Algorithm {
		t.Fatalf("incorrect algorith returned, not the same as saved value")
	}
	fmt.Printf("'Test get key' took %s\n", time.Since(startTime))
}

func createKeyFromEntry(b logical.Backend, storage logical.Storage, t *testing.T, entry jwt.KeyStorageEntry) (*logical.Response, error) {
	data := structs.Map(entry)

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("keys/%s", entry.Name),
		Data:      data,
	}

	startTime := time.Now()
	resp, err := b.HandleRequest(context.Background(), req)
	fmt.Printf("'Test create key' took %s\n", time.Since(startTime))
	return resp, err
}
