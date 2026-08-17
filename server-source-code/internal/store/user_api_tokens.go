package store

import (
	"context"
	"time"

	"github.com/PatchMon/PatchMon/server-source-code/internal/database"
	"github.com/PatchMon/PatchMon/server-source-code/internal/db"
	"github.com/PatchMon/PatchMon/server-source-code/internal/pgtime"
	"github.com/jackc/pgx/v5/pgtype"
)

// UserApiTokenStore manages long-lived user API tokens for automation.
type UserApiTokenStore struct {
	db database.DBProvider
}

func NewUserApiTokenStore(db database.DBProvider) *UserApiTokenStore {
	return &UserApiTokenStore{db: db}
}

func (s *UserApiTokenStore) List(ctx context.Context, userID string) ([]db.ListUserApiTokensRow, error) {
	d := s.db.DB(ctx)
	return d.Queries.ListUserApiTokens(ctx, userID)
}

func (s *UserApiTokenStore) GetByHash(ctx context.Context, tokenHash string) (db.GetUserApiTokenByHashRow, error) {
	d := s.db.DB(ctx)
	return d.Queries.GetUserApiTokenByHash(ctx, tokenHash)
}

func (s *UserApiTokenStore) Create(ctx context.Context, arg db.CreateUserApiTokenParams) (db.CreateUserApiTokenRow, error) {
	d := s.db.DB(ctx)
	return d.Queries.CreateUserApiToken(ctx, arg)
}

func (s *UserApiTokenStore) Delete(ctx context.Context, id string) error {
	d := s.db.DB(ctx)
	return d.Queries.DeleteUserApiToken(ctx, id)
}

func (s *UserApiTokenStore) UpdateLastUsed(ctx context.Context, id string) error {
	d := s.db.DB(ctx)
	return d.Queries.UpdateUserApiTokenLastUsed(ctx, id)
}

// UserApiTokenListItem is the safe JSON response for listing tokens (never exposes hash).
type UserApiTokenListItem struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

func RowToUserApiTokenListItem(r db.ListUserApiTokensRow) UserApiTokenListItem {
	return userApiTokenListItem(r.ID, r.Name, r.CreatedAt, r.ExpiresAt, r.LastUsedAt)
}

// CreateRowToUserApiTokenListItem converts the row returned by Create (a
// distinct sqlc type from ListUserApiTokensRow despite identical fields).
func CreateRowToUserApiTokenListItem(r db.CreateUserApiTokenRow) UserApiTokenListItem {
	return userApiTokenListItem(r.ID, r.Name, r.CreatedAt, r.ExpiresAt, r.LastUsedAt)
}

func userApiTokenListItem(id, name string, createdAt, expiresAt, lastUsedAt pgtype.Timestamptz) UserApiTokenListItem {
	return UserApiTokenListItem{
		ID:         id,
		Name:       name,
		CreatedAt:  createdAt.Time.UTC(),
		ExpiresAt:  pgtime.PtrTz(expiresAt),
		LastUsedAt: pgtime.PtrTz(lastUsedAt),
	}
}
