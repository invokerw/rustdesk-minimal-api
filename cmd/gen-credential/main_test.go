package main

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGenerateCredentialPair(t *testing.T) {
	t.Parallel()

	pair, err := generateCredentialPair("alice", "secret", bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("generateCredentialPair failed: %v", err)
	}

	username, hash, ok := strings.Cut(pair, ":")
	if !ok {
		t.Fatalf("pair %q is missing ':'", pair)
	}
	if username != "alice" {
		t.Fatalf("username = %q, want %q", username, "alice")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("secret")); err != nil {
		t.Fatalf("generated hash does not match password: %v", err)
	}
}

func TestGenerateCredentialPairRejectsBadInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		username string
		password string
		cost     int
	}{
		{name: "empty username", username: "", password: "secret", cost: bcrypt.DefaultCost},
		{name: "username with colon", username: "alice:ops", password: "secret", cost: bcrypt.DefaultCost},
		{name: "empty password", username: "alice", password: "", cost: bcrypt.DefaultCost},
		{name: "cost too high", username: "alice", password: "secret", cost: bcrypt.MaxCost + 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := generateCredentialPair(test.username, test.password, test.cost); err == nil {
				t.Fatal("generateCredentialPair succeeded, want error")
			}
		})
	}
}

func TestValidateUsernameTrimsWhitespace(t *testing.T) {
	t.Parallel()

	username, err := validateUsername("  alice  ")
	if err != nil {
		t.Fatalf("validateUsername failed: %v", err)
	}
	if username != "alice" {
		t.Fatalf("username = %q, want %q", username, "alice")
	}
}
