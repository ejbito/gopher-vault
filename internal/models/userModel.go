package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID			uuid.UUID	`gorm:"type:uuid;primary_key;"`
	FirstName	string
	LastName	string

	Email		string		`gorm:"unique"`
	Password	string
}

func (user*User) BeforeCreate(tx *gorm.DB) (err error) {
	user.ID = uuid.New()
	return
}