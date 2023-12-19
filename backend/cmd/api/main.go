package main

import (
	"fmt"

	"go-auth/internal/server"
)

func main() {
	server := server.NewServer()

	err := server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
		panic("cannot start server ")
	}
}
