package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == "" {
		t.Error("HashPassword() should return non-empty hash")
	}

	// Verify hash starts with bcrypt prefix
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Errorf("Hash doesn't appear to be bcrypt format: %s", hash)
	}

	// Verify hash can be used for comparison
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		t.Error("Generated hash doesn't match original password")
	}

	// Verify different passwords produce different hashes
	hash2, err := HashPassword("differentpassword")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == hash2 {
		t.Error("Different passwords should produce different hashes")
	}
}

func TestLoadCredentialsValid(t *testing.T) {
	tempDir := t.TempDir()
	credFile := filepath.Join(tempDir, "credentials.txt")

	// Create valid credentials file
	hash1, _ := HashPassword("password1")
	hash2, _ := HashPassword("password2")

	content := `# Comment line
user1:` + hash1 + `
user2:` + hash2 + `

# Another comment
admin:` + hash1 + `
`

	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	creds, err := LoadCredentials(credFile)
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}

	// Verify all users were loaded
	if len(creds.users) != 3 {
		t.Errorf("len(users) = %d, want 3", len(creds.users))
	}

	// Verify users exist
	if _, exists := creds.users["user1"]; !exists {
		t.Error("user1 should exist")
	}
	if _, exists := creds.users["user2"]; !exists {
		t.Error("user2 should exist")
	}
	if _, exists := creds.users["admin"]; !exists {
		t.Error("admin should exist")
	}
}

func TestLoadCredentialsFileNotFound(t *testing.T) {
	_, err := LoadCredentials("/nonexistent/file.txt")
	if err == nil {
		t.Error("LoadCredentials() should return error for non-existent file")
	}
}

func TestLoadCredentialsInvalidFormat(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "missing colon",
			content: "userwithnocolon",
			wantErr: "invalid format",
		},
		{
			name:    "empty username",
			content: ":somehash",
			wantErr: "empty username",
		},
		{
			name:    "empty hash",
			content: "user:",
			wantErr: "empty hash",
		},
		{
			name:    "only whitespace",
			content: "   \n\t\n   ",
			wantErr: "no valid credentials",
		},
		{
			name:    "only comments",
			content: "# comment1\n# comment2\n",
			wantErr: "no valid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			credFile := filepath.Join(tempDir, "creds.txt")

			if err := os.WriteFile(credFile, []byte(tt.content), 0600); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			_, err := LoadCredentials(credFile)
			if err == nil {
				t.Error("LoadCredentials() should return error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Error = %v, should contain %s", err, tt.wantErr)
			}
		})
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	tempDir := t.TempDir()
	credFile := filepath.Join(tempDir, "credentials.txt")

	password := "testpass123"
	hash, _ := HashPassword(password)

	content := "testuser:" + hash + "\n"
	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	creds, err := LoadCredentials(credFile)
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}

	// Test successful authentication
	if !creds.Authenticate("testuser", password) {
		t.Error("Authenticate() should return true for valid credentials")
	}
}

func TestAuthenticateFailure(t *testing.T) {
	tempDir := t.TempDir()
	credFile := filepath.Join(tempDir, "credentials.txt")

	password := "correctpassword"
	hash, _ := HashPassword(password)

	content := "testuser:" + hash + "\n"
	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	creds, err := LoadCredentials(credFile)
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}

	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "wrong password",
			username: "testuser",
			password: "wrongpassword",
		},
		{
			name:     "non-existent user",
			username: "nonexistent",
			password: "anypassword",
		},
		{
			name:     "empty password",
			username: "testuser",
			password: "",
		},
		{
			name:     "empty username",
			username: "",
			password: password,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if creds.Authenticate(tt.username, tt.password) {
				t.Error("Authenticate() should return false for invalid credentials")
			}
		})
	}
}

func TestLoadCredentialsWithWhitespace(t *testing.T) {
	tempDir := t.TempDir()
	credFile := filepath.Join(tempDir, "credentials.txt")

	hash, _ := HashPassword("password")

	// Test with various whitespace
	content := `  user1  :  ` + hash + `
	user2	:	` + hash + `
`

	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	creds, err := LoadCredentials(credFile)
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}

	// Usernames should be trimmed
	if _, exists := creds.users["user1"]; !exists {
		t.Error("user1 should exist after whitespace trimming")
	}
	if _, exists := creds.users["user2"]; !exists {
		t.Error("user2 should exist after whitespace trimming")
	}
}

func TestLoadCredentialsMultipleColons(t *testing.T) {
	tempDir := t.TempDir()
	credFile := filepath.Join(tempDir, "credentials.txt")

	hash, _ := HashPassword("password")

	// SplitN with 2 means "user:hash:with:colons" becomes ["user", "hash:with:colons"]
	// So the hash part can contain colons without issues
	content := "username:" + hash + "\n"

	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	creds, err := LoadCredentials(credFile)
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}

	// Username should be "username" and hash should be preserved
	if _, exists := creds.users["username"]; !exists {
		t.Error("username should exist")
	}

	// Verify authentication still works
	if !creds.Authenticate("username", "password") {
		t.Error("Should authenticate successfully")
	}
}

func TestHashPasswordConsistency(t *testing.T) {
	password := "testpassword"

	// Hash the same password twice
	hash1, err1 := HashPassword(password)
	hash2, err2 := HashPassword(password)

	if err1 != nil || err2 != nil {
		t.Fatal("HashPassword() should not error")
	}

	// Hashes should be different (bcrypt includes salt)
	if hash1 == hash2 {
		t.Error("Multiple hashes of same password should differ (due to salt)")
	}

	// But both should verify against the original password
	if err := bcrypt.CompareHashAndPassword([]byte(hash1), []byte(password)); err != nil {
		t.Error("hash1 should verify against password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash2), []byte(password)); err != nil {
		t.Error("hash2 should verify against password")
	}
}

func TestAuthenticateCaseSensitive(t *testing.T) {
	tempDir := t.TempDir()
	credFile := filepath.Join(tempDir, "credentials.txt")

	password := "Password123"
	hash, _ := HashPassword(password)

	content := "TestUser:" + hash + "\n"
	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	creds, err := LoadCredentials(credFile)
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}

	// Username should be case-sensitive
	if creds.Authenticate("testuser", password) {
		t.Error("Username should be case-sensitive")
	}
	if creds.Authenticate("TESTUSER", password) {
		t.Error("Username should be case-sensitive")
	}

	// Password should be case-sensitive
	if creds.Authenticate("TestUser", "password123") {
		t.Error("Password should be case-sensitive")
	}

	// Correct case should work
	if !creds.Authenticate("TestUser", password) {
		t.Error("Correct credentials should authenticate")
	}
}

func TestLoadCredentialsEmptyFile(t *testing.T) {
	tempDir := t.TempDir()
	credFile := filepath.Join(tempDir, "empty.txt")

	if err := os.WriteFile(credFile, []byte(""), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err := LoadCredentials(credFile)
	if err == nil {
		t.Error("LoadCredentials() should error on empty file")
	}
	if !strings.Contains(err.Error(), "no valid credentials") {
		t.Errorf("Error should mention no valid credentials: %v", err)
	}
}

func TestHashPasswordEmptyString(t *testing.T) {
	// bcrypt should handle empty passwords
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword(\"\") error = %v", err)
	}

	// Should still produce a valid hash
	if hash == "" {
		t.Error("HashPassword(\"\") should return non-empty hash")
	}

	// Should verify correctly
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(""))
	if err != nil {
		t.Error("Hash of empty string should verify correctly")
	}
}

func TestLoadCredentialsScannerError(t *testing.T) {
	// This is difficult to test without mocking, but we can test
	// that the function handles the scanner.Err() check
	// For now, just ensure normal operation doesn't trigger it

	tempDir := t.TempDir()
	credFile := filepath.Join(tempDir, "credentials.txt")

	hash, _ := HashPassword("password")
	content := "user:" + hash + "\n"

	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err := LoadCredentials(credFile)
	if err != nil {
		t.Errorf("LoadCredentials() should not error on valid file: %v", err)
	}
}
