package josejwt

import (
	"fmt"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/google/uuid"
)

// TokenCreateEntry is the exposed structure for creating a token
type TokenCreateEntry struct {
	TTL int `json:"ttl" structs:"ttl" mapstructure:"ttl"`

	ID string `json:"id" structs:"id" mapstructure:"id"`

	Claims map[string]string `json:"claims" structs:"claims" mapstructure:"claims"`

	RoleName string `json:"role_name" structs:"role_name" mapstructure:"role_name"`

	RoleID string `json:"role_id" structs:"role_id" mapstructure:"role_id"`

	KeyName string `json:"key_name" structs:"key_name" mapstructure:"key_name"`
}

func createJwtToken(createEntry TokenCreateEntry, roleEntry *RoleStorageEntry, keyEntry *KeyStorageEntry) ([]byte, error) {

	claims := jws.Claims{}

	id, _ := uuid.NewUUID()

	claims.SetJWTID(id.String())

	if roleEntry.Audience != "" {
		claims.SetAudience(roleEntry.Audience)
	}
	if roleEntry.Issuer != "" {
		claims.SetIssuer(roleEntry.Issuer)
	}
	if roleEntry.Subject != "" {
		claims.SetSubject(roleEntry.Subject)
	}
	if roleEntry.ExpirationTime {
		utc := time.Now().UTC().Add(time.Duration(createEntry.TTL) * time.Second)
		claims.SetExpiration(utc)
	}
	if roleEntry.NotBefore {
		claims.SetNotBefore(time.Now().UTC())
	}
	if roleEntry.IssuedAt {
		claims.SetIssuedAt(time.Now().UTC())
	}

	for claimType, value := range roleEntry.Claims {
		claims[claimType] = value
	}

	for _, claimType := range roleEntry.AllowedCustomClaims {
		if value, ok := createEntry.Claims[claimType]; ok {
			claims.Set(claimType, value)
		}
	}

	signingMethod := jws.GetSigningMethod(keyEntry.Algorithm)

	token := jws.NewJWT(claims, signingMethod)

	serializedToken, err := token.Serialize([]byte(keyEntry.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("signing failed: %s", err)
	}

	return serializedToken[:], nil
}

func (backend *JwtBackend) createToken(createEntry TokenCreateEntry, roleEntry *RoleStorageEntry, keyEntry *KeyStorageEntry) ([]byte, error) {

	switch roleEntry.Type {
	case "jws":
		return nil, nil
	case "jwt":
		return createJwtToken(createEntry, roleEntry, keyEntry)
	default:
		// throw an error
		return nil, fmt.Errorf("unsupported token type %s", roleEntry.Type)
	}

}
