package entity

import "github.com/google/uuid"

type User struct {
	Id       uuid.UUID
	Username string `json:"username"`
	Password string `json:"password"`
}
