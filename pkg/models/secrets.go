package models

import (
	"errors"
	"time"
)

var (
	ErrSecretNotFound                = errors.New("secret not found")
	ErrSecretNameExists              = errors.New("secret with the same name already exists")
	ErrSecretUidExists               = errors.New("secret with the same uid already exists")
	ErrSecretUpdatingOldVersion      = errors.New("trying to update old version of datasource")
	ErrSecretIsReadOnly              = errors.New("secret is readonly, can only be updated from configuration")
	ErrSecretAccessDenied            = errors.New("secret access denied")
	ErrSecretFailedGenerateUniqueUid = errors.New("failed to generate unique datasource ID")
	ErrSecretIdentifierNotSet        = errors.New("unique identifier and org id are needed to be able to get or delete a datasource")
)

type Secret struct {
	Id      int64 `json:"id"`
	OrgId   int64 `json:"orgId"`
	Version int   `json:"version"`

	Name           string            `json:"name"`
	Type           string            `json:"type"`
	SecureJsonData map[string][]byte `json:"secureJsonData"`
	ReadOnly       bool              `json:"readOnly"`

	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// ----------------------
// COMMANDS

// Also acts as api DTO
type AddSecretCommand struct {
	Name           string            `json:"name" binding:"Required"`
	Type           string            `json:"type" binding:"Required"`
	SecureJsonData map[string]string `json:"secureJsonData" binding:"Required"`

	OrgId                   int64             `json:"-"`
	ReadOnly                bool              `json:"-"`
	EncryptedSecureJsonData map[string][]byte `json:"-"`

	Result *Secret `json:"-"`
}

// Also acts as api DTO
type UpdateSecretCommand struct {
	Name           string            `json:"name" binding:"Required"`
	SecureJsonData map[string]string `json:"secureJsonData" binding:"Required"`
	Type           string            `json:"type"`
	Version        int               `json:"version"`

	OrgId                   int64             `json:"-"`
	Id                      int64             `json:"-"`
	ReadOnly                bool              `json:"-"`
	EncryptedSecureJsonData map[string][]byte `json:"-"`

	Result *Secret `json:"-"`
}

// DeleteSecretCommand will delete a Secret based on OrgID as well as the UID (preferred), ID, or Name.
// At least one of the UID, ID, or Name properties must be set in addition to OrgID.
type DeleteSecretCommand struct {
	ID    int64
	OrgID int64
	Name  string

	DeletedSecretsCount int64
}

// ---------------------
// QUERIES

type GetSecretsQuery struct {
	OrgId       int64
	SecretLimit int
	User        *SignedInUser
	Result      []*Secret
}

type GetSecretsByTypeQuery struct {
	Type   string
	Result []*Secret
}

// GetSecretQuery will get a Secret based on OrgID as well as the UID (preferred), ID, or Name.
// At least one of the UID, ID, or Name properties must be set in addition to OrgID.
type GetSecretQuery struct {
	Id   int64
	Uid  string
	Name string

	OrgId int64

	Result *Secret
}

// ---------------------
//  Permissions
// ---------------------

type SecretsPermissionFilterQuery struct {
	User    *SignedInUser
	Secrets []*Secret
	Result  []*Secret
}
