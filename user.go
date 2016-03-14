package main

type User struct {
	Id    string   `json:"id"`
	Name  string   `json:"name"`
	Email string   `json:"email"`
	Certs []string `json:"certs"`
}

type UserExtended struct {
	User
	Certs []Certificate `json:"certs"`
}
