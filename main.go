package main

import (
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var mySigningKey = []byte("mysupersecretphrase")

func main() {

	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/protected", handleProtected)
	http.ListenAndServe(":8080", nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	// 验证用户凭据
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username != "admin" || password != "password" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	//生成jwt
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write([]byte(tokenString))
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	//验证jwt
	tokenString := strings.Split(authHeader, " ")[1]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, nil
		}
		return mySigningKey, nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//获取jwt中的声明
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	//检查用户权限
	if claims["username"] != "admin" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Write([]byte("Welcome to the protected area"))
}
