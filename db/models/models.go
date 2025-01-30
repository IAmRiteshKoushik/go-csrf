package models

import (
	"go-csrf/randomstrings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type User struct {
	Username     string
	PasswordHash string
	Role         string
}

type TokenClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const RefreshTokenValidTime = time.Hour * 72
const AuthTokenValidTime = time.Minute * 15

func GenerateCSRFSecret() (string, error) {
	return randomstrings.GenerateRandomString(32)
}
