package main

import (
	"fmt"
	"github.com/phillipahereza/tapo"
	"log"
)

func main() {
	plug, err := tapo.NewP100("192.168.0.138", "", "")
	if err != nil {
		log.Fatal(err)
	}

	key, err := plug.Handshake()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(key)
}
