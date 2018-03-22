package josejwt_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	jwt "github.com/wenisman/vault_jwt_plugin/JWT-Secrets-Plugin/plugin"

	"github.com/hashicorp/vault/logical"
	"github.com/stretchr/testify/assert"
)

func failed(resp *logical.Response, err error) error {
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("response was nil")
	}
	if resp.IsError() {
		return fmt.Errorf("response was error: %#v,  %s", resp.Data, resp.Error())
	}
	return nil
}

func TestCreateToken(t *testing.T) {
	assert := assert.New(t)

	b, storage := getTestBackend(t)
	keyEntry := jwt.KeyStorageEntry{
		Name:       "test-key",
		Algorithm:  crypto.SigningMethodHS256.Name,
		PrivateKey: "test-key",
	}
	if err := failed(createKeyFromEntry(b, storage, t, keyEntry)); err != nil {
		t.Fatalf("could not create key: %s", err)
	}

	roleName := "test_role"
	roleEntry := jwt.RoleStorageEntry{
		Name: roleName,
		Type: "jwt",
		Key:  keyEntry.Name,
		Claims: map[string]string{
			"custom":      "custom-value",
			"overridable": "overridable-value",
		},
		AllowedCustomClaims: []string{"overridable"},
		Issuer:              "test-issuer",
		Subject:             "test-subject",
		Audience:            "test-audience",
		NotBefore:           true,
		ExpirationTime:      true,
		IssuedAt:            true,
		TokenTTL:            100,
		MaxTokenTTL:         100,
	}

	if err := failed(createRoleFromEntry(b, storage, t, roleEntry)); err != nil {
		t.Fatalf("could not create role: %s", err)
	}

	req := &logical.Request{
		Storage: storage,
	}

	resp, err := createToken(req, b, t, roleName, "10s", map[string]string{
		"overridable": "overridden-value",
		"custom":      "not-allowed-value",
	})
	if err = failed(resp, err); err != nil {
		t.Fatalf("createToken returned error: %s", err)
	}

	fmt.Printf("response: %#v\n", resp.Data)

	assert.Contains(resp.Data, "token")
	token, ok := resp.Data["token"]
	assert.True(ok, "token should be in data")

	tokenString, ok := token.(string)
	assert.True(ok, "token should be a string")

	jwt, err := jws.ParseJWT([]byte(tokenString))
	assert.Nil(err, "token should be parsable")

	alg := jws.GetSigningMethod(keyEntry.Algorithm)
	assert.NoError(jwt.Validate([]byte(keyEntry.PrivateKey), alg), "token should be valid")

	fmt.Printf("claims: %#v", jwt.Claims())

	claims := jwt.Claims()
	issuer, _ := claims.Issuer()
	assert.Equal(roleEntry.Issuer, issuer, "iss")

	aud, _ := claims.Audience()
	assert.Equal(roleEntry.Audience, aud[0], "aud")

	sub, _ := claims.Subject()
	assert.Equal(roleEntry.Subject, sub, "sub")

	custom := claims.Get("custom")
	assert.Equal(roleEntry.Claims["custom"], custom, "custom should not be overwritten")

	overridable := claims.Get("overridable")
	assert.Equal("overridden-value", overridable, "overridable should be overwritten")

	issuedAt, _ := claims.IssuedAt()
	assert.WithinDuration(time.Now(), issuedAt, time.Second, "iss should be correct")

	nbf, _ := claims.NotBefore()
	assert.WithinDuration(time.Now(), nbf, time.Second, "nbf should be correct")

	exp, _ := claims.Expiration()
	fmt.Println("exp", exp)
	assert.WithinDuration(time.Now().Add(time.Second*time.Duration(roleEntry.TokenTTL)), exp, time.Second, "exp should be correct")

}

func TestIssueValidateToken(t *testing.T) {
	// TODO: implemented validation
	// b, storage := getTestBackend(t)
	// roleName := "test_role"
	// resp, _ := createSampleRole(b, storage, roleName, "")

	// req := &logical.Request{
	// 	Storage:     storage,
	// 	DisplayName: fmt.Sprintf("test-%s", roleName),
	// }

	// resp, err := createToken(req, b, t, roleName, "")
	// if err != nil || (resp != nil && resp.IsError()) {
	// 	t.Fatalf("err:%s resp:%#v\n", err, resp)
	// }

	// if resp.Data["ClientToken"] == "" {
	// 	t.Fatal("no token returned\n")
	// }

	// clientToken := resp.Data["ClientToken"].(string)
	// log.Println(clientToken)

	// // with a 1 second timeout this should still return a valid token
	// time.Sleep(time.Duration(1) * time.Second)
	// validateToken(req, b, t, clientToken, roleName, true)
	// validateToken(req, b, t, clientToken, roleName, true)

	// // with a two second timeout this should fail vaildation
	// time.Sleep(time.Duration(2) * time.Second)
	// validateToken(req, b, t, clientToken, roleName, false)

	// // now to recreate a token and test its valid once again
	// resp, err = createToken(req, b, t, roleName, "")
	// if err != nil || (resp != nil && resp.IsError()) {
	// 	t.Fatalf("err:%s resp:%#v\n", err, resp)
	// }

	// if resp.Data["ClientToken"] == "" {
	// 	t.Fatal("no token returned\n")
	// }

	// clientToken = resp.Data["ClientToken"].(string)
	// validateToken(req, b, t, clientToken, roleName, true)
}

// create the token given the parameters
func createToken(req *logical.Request, b logical.Backend, t *testing.T, roleName string, ttl string, claims map[string]string) (*logical.Response, error) {
	data := map[string]interface{}{
		"role_name": roleName,
		"token_ttl": ttl,
	}

	// set the claims to use if specified
	if claims != nil {
		data["claims"] = claims
	}

	req.Operation = logical.UpdateOperation
	req.Path = fmt.Sprintf("token/issue/%s", roleName)
	req.Data = data

	start := time.Now()
	resp, err := b.HandleRequest(context.Background(), req)
	fmt.Printf("Issue Token took %s\n", time.Since(start))

	return resp, err
}

// validate the returned token
func validateToken(req *logical.Request, b logical.Backend, t *testing.T, clientToken string, roleName string, result bool) {
	data := map[string]interface{}{
		"token":     clientToken,
		"role_name": roleName,
	}

	req.Path = "token/validate"
	req.Data = data

	start := time.Now()

	resp, err := b.HandleRequest(context.Background(), req)
	fmt.Printf("Validate Token took %s\n", time.Since(start))
	if err != nil || (resp != nil && resp.IsError()) {
		if err.Error() != "token is expired" {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		} else {
			return
		}
	}

	if resp.Data["is_valid"] != result {
		t.Fatalf("incorrect validation result")
	}
}

// create the role with the specified name
func createSampleRole(b logical.Backend, storage logical.Storage, roleName string, claim string) (*logical.Response, error) {
	data := map[string]interface{}{
		"type":         "jwt",
		"token_ttl":    2,
		"named_claims": []string{claim},
	}

	req := &logical.Request{
		Operation:   logical.CreateOperation,
		Path:        fmt.Sprintf("role/%s", roleName),
		Storage:     storage,
		Data:        data,
		DisplayName: fmt.Sprintf("test-%s", roleName),
	}

	return b.HandleRequest(context.Background(), req)
}

func createClaim(b logical.Backend, storage logical.Storage, name string, claims map[string]string) (*logical.Response, error) {

	data := map[string]interface{}{
		"claims": claims,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("claims/%s", name),
		Storage:   storage,
		Data:      data,
	}

	return b.HandleRequest(context.Background(), req)
}
