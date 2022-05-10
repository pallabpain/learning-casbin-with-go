package main

import (
	"fmt"
	"log"
)

const (
	CONF_DIR = "./conf"
)

func main() {
	enforcer, err := NewEnforcer()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(enforcer)
}
