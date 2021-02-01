package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)


func setSession(userName string, response http.ResponseWriter) {
     value := map[string]string{
         "name": userName,
     }
     if encoded, err := CookieHandler.Encode("session", value); err == nil {
         cookie := &http.Cookie{
             Name:  "session",
             Value: encoded,
             Path:  "/",
         }
         http.SetCookie(response, cookie)
     }
 }

 func getUserName(request *http.Request) (userName string) {
     if cookie, err := request.Cookie("session"); err == nil {
         cookieValue := make(map[string]string)
         if err = CookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
             userName = cookieValue["name"]
         }
     }
     return userName
 }

 func clearSession(response http.ResponseWriter) {
     cookie := &http.Cookie{
         Name:   "session",
         Value:  "",
         Path:   "/",
         MaxAge: -1,
     }
     http.SetCookie(response, cookie)
 }

func isUserValid(username string, password string) (userName string, valid bool) {
	valid = false
	if username == "user" && password == "password" {
		valid = true
		return username, valid
	} else {
		return username, valid
	}
}

func authenticate(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	name := r.FormValue("programName")
	password := r.FormValue("programPassword")

	if len(name) == 0 || len(password) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Please provide name and password to obtain the token"))
		return
	}

	userName, valid := isUserValid(name, password)
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Name and password do not match"))
		return
	}
	token, err := getToken(userName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error generating JWT token: " + err.Error()))
	} else {
		session.Values["authenticated"] = true
		session.Save(r, w)
		w.Header().Set("Authorization", "Bearer "+token)
		fmt.Println("authenticate() : token : ", token)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Token: " + token))

	}
}

func authenticateWithRedirect(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	name := r.FormValue("programName")
	password := r.FormValue("programPassword")

	if len(name) == 0 || len(password) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Please provide name and password to obtain the token"))
		return
	}

	userName, valid := isUserValid(name, password)
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Name and password do not match"))
		return
	}
	token, err := getToken(userName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error generating JWT token: " + err.Error()))
	} else {
		w.Header().Set("Authorization", "Bearer "+token)
		fmt.Println("authenticateWithRedirect() : token : ", token)
		//w.WriteHeader(http.StatusOK)
		//w.Write([]byte("Token: " + token))
		//setSession(name, w)
		session.Values["authenticated"] = true
		session.Save(r, w)
		http.Redirect(w, r, "/home", http.StatusFound)
	}
}


func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tokenString := r.Header.Get("Authorization")
		fmt.Println("authMiddleware() : tokenString : ", tokenString)
		if len(tokenString) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing Authorization Header"))
			return
		}
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
		claims, err := verifyToken(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Error verifying JWT token: " + err.Error()))
			return
		}
		name := claims.(jwt.MapClaims)["name"].(string)
		role := claims.(jwt.MapClaims)["role"].(string)

		fmt.Println("name : ", name)
		fmt.Println("role : ",  role)

		r.Header.Set("name", name)
		r.Header.Set("role", role)

		next.ServeHTTP(w, r)
	})
}
