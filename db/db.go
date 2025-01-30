package db

import (
	"errors"
	"go-csrf/db/models"
)

var users = map[string]models.User{}

func InitDB() {

}

func StoreUser(username string, password string, role string) (uuid string, err error) {

}

func DeleteUser() {

}

func FetchUserById() {

}

func FetchUserByUsername(username string) (models.User, string, error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}
	return models.User{}, "", errors.New("User not found that matches the given username")
}

func StoreRefreshToken() {

}

func DeleteRefreshToken() {

}

func CheckRefreshToken() bool {

}

func LogUserIn() {

}

func generateBcryptHash() {

}

func checkPasswordAgainstHash() error {

}
