package main

import (
	"go-csrf/db"
	"go-csrf/server"
	"go-csrf/server/middleware/myJwt"
	"log"
)

var host = "localhost"
var port = "9000"

func main() {
	db.InitDB()

	jwtErr := myJwt.InitJwt()
	if jwtErr != nil {
		log.Println("Error initializing the JWT!")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting a server")
		log.Fatal(serverErr)
	}
}
