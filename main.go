package main

import (
	"crypto"
	"log"

	"github.com/google/uuid"
)

type signCloser interface {
	crypto.Signer
	Close() error
}

func main() {
	id := uuid.NewString()

	_, err := createKey(id)
	if err != nil {
		log.Printf("error creating key: %v", err)
	} else {
		log.Printf("created key with name %s", id)
	}
}
