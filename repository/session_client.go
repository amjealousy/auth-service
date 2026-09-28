package repository

import (
	"auth-service/entity"
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type SessionRepository interface {
	CreateSession(ctx context.Context, session entity.SessionDTO, userId uuid.UUID) (uuid.UUID, error)
	WithTx(tx pgx.Tx) SessionRepository
}

type SessionRepositoryImpl struct {
	ctx       context.Context
	connector *DBTX
	query     *Queries
}

func (s SessionRepositoryImpl) WithTx(tx pgx.Tx) SessionRepository {
	return &SessionRepositoryImpl{
		connector: s.connector,
		query:     s.query.WithTx(tx),
	}
}

func (s SessionRepositoryImpl) CreateSession(ctx context.Context, session entity.SessionDTO, userId uuid.UUID) (uuid.UUID, error) {

	params := CreateSessionParams{GoogleToPgtypeUuid(userId), session.Refresh}
	p, err := s.query.CreateSession(ctx, params)
	if p.Valid {
		parse, err := uuid.FromBytes(p.Bytes[:])
		return parse, err
	} else {
		return uuid.Nil, err
	}
}

func NewSessionRepository(connector *DBTX) *SessionRepositoryImpl {
	q := New(*connector)
	return &SessionRepositoryImpl{
		connector: connector,
		query:     q,
	}
}

func GoogleToPgtypeUuid(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{
		Bytes: [16]byte(id[:]), // преобразование uuid.UUID в байтовый массив
		Valid: true,
	}
}
