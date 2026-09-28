package entity

import (
	"github.com/google/uuid"
)

type SessionDTO struct {
	ID      uuid.UUID
	Refresh string
	scope   string
	revoked bool
	expired bool
}

func (dto *SessionDTO) GetScope() string {
	return dto.scope
}

func NewSession(scope string, refresh string) SessionDTO {
	return SessionDTO{
		scope:   scope,
		Refresh: refresh,
	}
}
