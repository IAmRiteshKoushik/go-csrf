package middleware

import (
	"github.com/justinas/alice"
	"go-csrf/db"
	"go-csrf/server/middleware/myJwt"
	"go-csrf/server/templates"
	"log"
	"net/http"
	"strings"
	"time"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	// This helps in recoery incase the system panics (it wraps things up in a
	// 500 internal server error)
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panic("Recovered!")
				http.Error(w, http.StatusText(http.StatusInternalServerError), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "/logout", "/deleteUser": // protected
			log.Println("In auth restricted section")

			AuthCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! No auth cookie")
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusUnauthorized), 401)
			} else if authErr != nil {
				log.Panicf("panic: %+v", authErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusInternalServerError), 500)
			}

			RefreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! No refresh cookies")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)
				return
			} else if refreshErr != nil {
				log.Panicf("panic: %+v", refreshErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusInternalServerError), 500)
				return
			}

			requestCsrfToken := grabCsrfFromReq(r)
			log.Println(requestCsrfToken)

			authTokenString, refreshTokenString, csrfSecret, err :=
				myJwt.CheckAndRefreshTokens(
					AuthCookie.Value,
					RefreshCookie.Value,
					requestCsrfToken,
				)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized attempt! JWT's not valid!")
					http.Error(w, http.StatusText(http.StatusUnauthorized), 401)
					return
				} else {
					log.Panic("Err not nil")
					log.Panicf("panic: %+v", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), 500)
					return
				}
			}
			log.Println("successfully recreated JWTs")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
		default: // unprotected routes
			// no checks necessary
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{
			CsrfSecret:    csrfSecret,
			SecretMessage: "Hello Ritesh"},
		)
	case "/login":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage{false, ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)
			user, uuid, loginErr := db.LogUserIn(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""))
			log.Println(user, uuid, loginErr)
			if loginErr != nil {
				log.Println(loginErr)
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, user.Role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage{false, ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)
			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
			if err == nil {
				// Username not available
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				role := "user"
				uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), 500)
				}
				log.Println("uuid: " + uuid)
				// If we have successfully registered the user, then we would have to
				// create the cookies
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), 500)
				}

				log.Println("Tokens generated")
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", 302)
	case "/deleteUser":
		log.Println("Deleting the user")
		AuthCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie {
			log.Println("Unauthorized attempt! No auth cookie")
			nullifyTokenCookies(&w, r)
			http.Redirect(w, r, "/login", 302)
		} else if authErr != nil {
			log.Panicf("panic: %+v", authErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		uuid, uuidErr := myJwt.GrabUUID(AuthCookie.Value)
		if uuidErr != nil {
			log.Panicf("panic: %+v", uuidErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}
		db.DeleteUser(uuid)
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/register", 302)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	// Revoke all cookies (auth-token and refresh-token)
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour), // immediately expiring it
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	// We are also revoking the refresh-token so that you cannot use it to
	// get any more JWTs in-case you have kept it somewhere else and can
	// manage to tamper the cookies on the browser side
	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		// do nothing
		return
	} else if refreshErr != nil {
		log.Panicf("panic: %+v", refreshErr)
		http.Error(*w, http.StatusText(http.StatusInternalServerError), 500)
	}
	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)
	log.Println("Cookie setting done")
	return
}

func grabCsrfFromReq(r *http.Request) string {
	// You can send CSRF token either in a form or inside a header
	csrfFromForm := r.FormValue("X-CSRF-Token")
	if csrfFromForm != "" {
		return csrfFromForm
	}
	return r.Header.Get("X-CSRF-Token")
}
