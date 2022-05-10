package main

type GroupingPolicy struct {
	Subject string
	Role    string
	Domain  string
}

type AuthorizationRequest struct {
	Subject string
	Domain  string
	Object  string
	Action  string
}
