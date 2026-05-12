package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Credentials manages username/password authentication
type Credentials struct {
	users map[string]string // username -> bcrypt hash
}

// LoadCredentials reads a credentials file and returns a Credentials instance
// File format: username:bcrypt_hash (one per line)
// Lines starting with # are comments, blank lines are ignored
func LoadCredentials(path string) (*Credentials, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path from CLI flag/config
	if err != nil {
		return nil, fmt.Errorf("failed to open credentials file: %w", err)
	}
	defer func() { _ = file.Close() }()

	creds := &Credentials{
		users: make(map[string]string),
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format at line %d: expected 'username:hash'", lineNum)
		}

		username := strings.TrimSpace(parts[0])
		hash := strings.TrimSpace(parts[1])

		if username == "" {
			return nil, fmt.Errorf("empty username at line %d", lineNum)
		}
		if hash == "" {
			return nil, fmt.Errorf("empty hash for user %s at line %d", username, lineNum)
		}

		creds.users[username] = hash
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading credentials file: %w", err)
	}

	if len(creds.users) == 0 {
		return nil, fmt.Errorf("no valid credentials found in file")
	}

	return creds, nil
}

// Authenticate verifies a username and password combination
// Returns true if valid, false otherwise
func (c *Credentials) Authenticate(username, password string) bool {
	hash, exists := c.users[username]
	if !exists {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashPassword creates a bcrypt hash of the given password
// Uses bcrypt.DefaultCost for the cost parameter
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}
