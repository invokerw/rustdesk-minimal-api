package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	cost := flag.Int("cost", bcrypt.DefaultCost, "bcrypt cost")
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("RustDesk minimal API credential generator")
	fmt.Printf("bcrypt cost: %d\n\n", *cost)

	username, err := promptUsername(reader)
	if err != nil {
		log.Fatal(err)
	}

	password, err := promptMatchingPassword(reader)
	if err != nil {
		log.Fatal(err)
	}

	pair, err := generateCredentialPair(username, password, *cost)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println()
	fmt.Println("Credential pair:")
	fmt.Println(pair)
	fmt.Println()
	fmt.Printf("Example:\n  go run . -credential '%s'\n", pair)
}

func promptUsername(reader *bufio.Reader) (string, error) {
	for {
		fmt.Print("Username: ")
		input, err := readLine(reader)
		if err != nil {
			return "", err
		}
		username, err := validateUsername(input)
		if err == nil {
			return username, nil
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
	}
}

func promptMatchingPassword(reader *bufio.Reader) (string, error) {
	for {
		password, err := promptPassword(reader, "Password: ")
		if err != nil {
			return "", err
		}
		confirm, err := promptPassword(reader, "Confirm password: ")
		if err != nil {
			return "", err
		}
		if password == "" {
			fmt.Fprintln(os.Stderr, "Error: password cannot be empty")
			fmt.Fprintln(os.Stderr)
			continue
		}
		if password != confirm {
			fmt.Fprintln(os.Stderr, "Error: passwords do not match")
			fmt.Fprintln(os.Stderr)
			continue
		}
		return password, nil
	}
}

func promptPassword(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		password, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(password), nil
	}
	return readLine(reader)
}

func generateCredentialPair(username, password string, cost int) (string, error) {
	username, err := validateUsername(username)
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", errors.New("password cannot be empty")
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", fmt.Errorf("cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("generate bcrypt hash: %w", err)
	}
	return username + ":" + string(hash), nil
}

func validateUsername(input string) (string, error) {
	username := strings.TrimSpace(input)
	if username == "" {
		return "", errors.New("username cannot be empty")
	}
	if strings.Contains(username, ":") {
		return "", errors.New("username cannot contain ':'")
	}
	return username, nil
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if errors.Is(err, io.EOF) && line == "" {
		return "", io.EOF
	}
	return line, nil
}
