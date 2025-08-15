package main

import "math/rand"

func randomUserAgent() string {
	if len(userAgents) == 0 {
		return "sqry"
	}
	return userAgents[rand.Intn(len(userAgents))]
}
