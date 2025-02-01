package myJwt

import (
	"crypto/rsa"
	"errors"
	"go-csrf/db"
	"go-csrf/db/models"
	"log"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	privateKeyPath = "keys/app.rsa"
	publicKeyPath  = "keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func InitJwt() error {
	signBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	return nil
}

func CreateNewTokens(uuid, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {
	// generate the csrf secret
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}
	// generating the refresht token
	refreshTokenString, err = CreateRefreshTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	// generate the auth token
	authTokenString, err = CreateAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	log.Printf("CSRF Generated: %v", csrfSecret)
	return
}

func CheckAndRefreshTokens(oldAuthTokenString, oldRefreshTokenString, oldCSrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {

	if oldCSrfSecret == "" {
		log.Println("No CSRF token!")
		err = errors.New("Unauthorized")
		return
	}

	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}
	if oldCSrfSecret != authTokenClaims.Csrf {
		log.Println("CSRF token doesn't match JWT")
		err = errors.New("Unauthorized")
		return
	}

	if authToken.Valid {
		log.Println("Auth token is valid")

		newCsrfSecret = authTokenClaims.Csrf
		newRefreshTokenString, err = UpdateRefreshTokenExp(oldRefreshTokenString)
		newAuthTokenString = oldAuthTokenString
		return
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		log.Println("Auth token is not valid")
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			log.Println("Auth token is expired")

			newAuthTokenString, newCsrfSecret, err = UpdateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)
			if err != nil {
				return
			}
			newRefreshTokenString, err = UpdateRefreshTokenCsrf(oldRefreshTokenString, newCsrfSecret)
			if err != nil {
				return
			}
			newRefreshTokenString, err = UpdateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
			if err != nil {
				return
			}
		} else {
			log.Println("Error in auth token")
			err = errors.New("Error in auth token")
			return
		}
	} else {
		log.Println("Error in auth token")
		err = errors.New("Error in auth token")
		return
	}
	err = errors.New("Unauthorized")
	return
}

func CreateAuthTokenString(uuid, role, csrfSecret string) (authTokenString string, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExp,
		},
		Role: role,
		Csrf: csrfSecret,
	}
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	authTokenString, err = authJwt.SignedString(signKey)
	return
}

func CreateRefreshTokenString(uuid, role, csrfSecret string) (refreshTokenString string, err error) {
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}
	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        refreshJti,
			Subject:   uuid,
			ExpiresAt: refreshTokenExp,
		},
		Role: role,
		Csrf: csrfSecret,
	}
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)
	log.Println(refreshTokenString)
	return
}

func UpdateRefreshTokenExp(oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: refreshTokenExp,
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: oldRefreshTokenClaims.Csrf,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func UpdateAuthTokenString(refreshTokenString string, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("Error reading JWT claims")
		return
	}

	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id) {
		if refreshToken.Valid {
			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})
			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok {
				err = errors.New("Error reading jwt claims")
				return
			}

			csrfSecret, err = models.GenerateCSRFSecret()
			if err != nil {
				return
			}

			CreateAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)
			return
		} else {
			log.Println("refreshToken has expired")
			db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

			err = errors.New("Unauthorized")
			return
		}
	} else {
		log.Println("Refresh token has been revoked")
		err = errors.New("Unauthorized")
		return
	}
}

func RevokeRefreshToken(refreshTokenString string) error {
	// use the refresh token string that this function will receive to get your
	// refresh token and use the refresh token to get the refresh token claims
	// deleting the refresh token using the method in the db package

	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return errors.New("Could not parse refresh token with claims")
	}
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return errors.New("Could not read refresh token claims")
	}
	db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)
	return nil
}

func UpdateRefreshTokenCsrf(oldRefreshTokenString, newCsrfString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}
	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt,
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: newCsrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func GrabUUID(authTokenString string) (string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return "", errors.New("Error fetching claims")
	})

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("Error fetching claims")
	}
	return authTokenClaims.StandardClaims.Subject, nil
}
