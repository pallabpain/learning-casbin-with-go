package main

import (
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

	err = enforcer.AddGroupingPolicies(createTestGroupingPolicies())
	if err != nil {
		log.Panicln(err)
	}

	ok, err := enforcer.IsAuthorized(AuthorizationRequest{
		Subject: "user2",
		Domain:  "project1",
		Object:  "vm",
		Action:  "write",
	})
	if err != nil {
		log.Panicln(err)
	}

	if ok {
		log.Println("authorized")
	} else {
		log.Println("unauthorized")
	}
}

func createTestGroupingPolicies() []GroupingPolicy {
	var policies []GroupingPolicy

	policies = append(policies, GroupingPolicy{
		Subject: "user1",
		Role:    "admin",
		Domain:  "project1",
	})

	policies = append(policies, GroupingPolicy{
		Subject: "user2",
		Role:    "member",
		Domain:  "project1",
	})

	return policies
}
