package josejwt

import (
	"context"
	"fmt"

	"github.com/fatih/structs"
	"github.com/google/uuid"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

// basic schema for the creation of the role, this will map the fields coming in from the
// vault request field map
var createRoleSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "The name of the role to be created.",
	},
	"type": {
		Type:        framework.TypeString,
		Description: "The type of token returned (jwe|jwt|jws).",
	},
	"key": {
		Type:        framework.TypeString,
		Description: "The name of the key to use for signing/encryption.",
	},
	"token_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The default TTL of tokens created through this role.",
		Default:     600,
	},
	"max_token_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The maximum TTL of tokens created through this role.",
		Default:     6000,
	},
	"claims": {
		Type: framework.TypeKVPairs,
		Description: `The structure of the claims to be added to the token.
JWT tokens have some default claims (exp, nbf, iat, jwt) which will automatically
be set to appropriate values when a token is generated. To disable any of these default claims,
set the claim to "false" in this parameter.`,
	},
	"allowed_custom_claims": {
		Type:        framework.TypeStringSlice,
		Description: "Array of claims which will be accepted as parameters in the issue request and used instead of the values set in the Claims map.",
		Default:     false,
	},

	"iss": {Type: framework.TypeString, Description: "Issuer"},
	"sub": {Type: framework.TypeString, Description: "Subject"},
	"aud": {Type: framework.TypeString, Description: "Audience"},
	"nbf": {Type: framework.TypeBool, Default: true, Description: "Not Before"},
	"iat": {Type: framework.TypeBool, Default: true, Description: "Issued At"},
	"exp": {Type: framework.TypeBool, Default: true, Description: "Expiration Time"},
}

// remove the specified role from the storage
func (backend *JwtBackend) removeRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to remove, missing role name"), nil
	}

	// get the role to make sure it exists and to get the role id
	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// remove the role
	if err := backend.deleteRoleEntry(ctx, req.Storage, roleName); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Unable to remove role %s", roleName)), err
	}

	return &logical.Response{}, nil
}

// read the current role from the inputs and return it if it exists
func (backend *JwtBackend) readRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("Error reading role"), err
	}

	roleDetails := structs.New(role).Map()
	delete(roleDetails, "role_id")

	return &logical.Response{Data: roleDetails}, nil
}

// create the role within plugin, this will provide the access for applications
// to be able to create tokens down the line
func (backend *JwtBackend) createRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("Role name not supplied"), nil
	}

	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("Error reading role"), err
	}

	if role == nil {
		role = new(RoleStorageEntry)
		// creating a new role
		if err := mapstructure.Decode(data.Raw, &role); err != nil {
			return logical.ErrorResponse("creating role - error decoding role"), err
		}

		// set the role ID
		roleID, _ := uuid.NewUUID()
		role.RoleID = roleID.String()

	} else {

		update := make(map[string]interface{})
		for key, value := range data.Raw {
			if key != "name" && key != "type" {
				update[key] = value
			}
		}

		if err := mapstructure.Decode(data.Raw, &role); err != nil {
			return logical.ErrorResponse("updating role - error decoding update"), err
		}
	}

	if err := backend.setRoleEntry(ctx, req.Storage, *role); err != nil {
		return logical.ErrorResponse("Error saving role"), err
	}

	roleDetails := map[string]interface{}{
		"role_id": role.RoleID,
	}
	return &logical.Response{Data: roleDetails}, nil
}

// set up the paths for the roles within vault
func pathRole(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern: fmt.Sprintf("role/%s", framework.GenericNameRegex("name")),
			Fields:  createRoleSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.createRole,
				logical.UpdateOperation: backend.createRole,
				logical.ReadOperation:   backend.readRole,
				logical.DeleteOperation: backend.removeRole,
			},
		},
	}

	return paths
}
