package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netutil/internal/auth"
)

var (
	port         = flag.String("port", "8080", "Port to listen on")
	workspaceDir = flag.String("workspace", "", "Path to workspace directory to serve")
	credsFile    = flag.String("credentials", "", "Path to credentials file (username:bcrypt_hash)")
	listenAddr   = flag.String("addr", "0.0.0.0", "Address to listen on")
	tlsCert      = flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey       = flag.String("tls-key", "", "TLS private key file (enables HTTPS)")
	hashPassword = flag.String("hash", "", "Hash a password and exit (utility mode)")
	showVersion  = flag.Bool("version", false, "Show version")
	version      = "dev"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "NetUtil File Server v%s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  Server mode:\n")
		fmt.Fprintf(os.Stderr, "    %s -workspace /opt/netutil/workspace -credentials /etc/netutil/fileserver.creds\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Hash password:\n")
		fmt.Fprintf(os.Stderr, "    %s -hash mypassword\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    echo -n 'mypassword' | %s -hash -\n", os.Args[0])
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("netutil-fileserver %s\n", version)
		os.Exit(0)
	}

	// Hash mode - hash a password and exit
	if *hashPassword != "" {
		var password string
		if *hashPassword == "-" {
			// Read from stdin
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				password = scanner.Text()
			} else {
				log.Fatal("ERROR: Failed to read password from stdin")
			}
		} else {
			password = *hashPassword
		}

		hash, err := auth.HashPassword(password)
		if err != nil {
			log.Fatalf("ERROR: Failed to hash password: %v", err)
		}
		fmt.Println(hash)
		os.Exit(0)
	}

	if *workspaceDir == "" {
		log.Fatal("ERROR: -workspace flag is required")
	}
	if *credsFile == "" {
		log.Fatal("ERROR: -credentials flag is required")
	}

	// Validate workspace directory exists
	absWorkspace, err := filepath.Abs(*workspaceDir)
	if err != nil {
		log.Fatalf("ERROR: Invalid workspace path: %v", err)
	}
	info, err := os.Stat(absWorkspace)
	if err != nil {
		log.Fatalf("ERROR: Cannot access workspace directory: %v", err)
	}
	if !info.IsDir() {
		log.Fatalf("ERROR: Workspace path is not a directory: %s", absWorkspace)
	}

	// Load credentials
	creds, err := auth.LoadCredentials(*credsFile)
	if err != nil {
		log.Fatalf("ERROR: Failed to load credentials: %v", err)
	}

	// Create file server
	fileServer := http.FileServer(http.Dir(absWorkspace))

	// Wrap with authentication and logging middleware
	handler := loggingMiddleware(basicAuthMiddleware(creds, fileServer))

	// Add CORS headers
	handler = corsMiddleware(handler)

	addr := fmt.Sprintf("%s:%s", *listenAddr, *port)
	log.Printf("Starting NetUtil File Server v%s", version)
	log.Printf("Serving workspace: %s", absWorkspace)
	log.Printf("Listening on: %s", addr)

	// Check if TLS is enabled
	useTLS := *tlsCert != "" && *tlsKey != ""

	if useTLS {
		// Validate TLS certificate and key files exist
		if _, err := os.Stat(*tlsCert); err != nil {
			log.Fatalf("ERROR: TLS certificate file not found: %s", *tlsCert)
		}
		if _, err := os.Stat(*tlsKey); err != nil {
			log.Fatalf("ERROR: TLS key file not found: %s", *tlsKey)
		}

		log.Printf("TLS enabled with certificate: %s", *tlsCert)
		log.Printf("Access URL: https://%s", addr)
		if err := http.ListenAndServeTLS(addr, *tlsCert, *tlsKey, handler); err != nil {
			log.Fatalf("ERROR: HTTPS server failed: %v", err)
		}
	} else {
		log.Printf("WARNING: Running without TLS encryption - credentials transmitted in cleartext")
		log.Printf("Access URL: http://%s", addr)
		if err := http.ListenAndServe(addr, handler); err != nil {
			log.Fatalf("ERROR: HTTP server failed: %v", err)
		}
	}
}

// basicAuthMiddleware implements HTTP Basic Authentication
func basicAuthMiddleware(creds *auth.Credentials, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			sendAuthRequired(w)
			return
		}

		if !creds.Authenticate(username, password) {
			log.Printf("AUTH FAILED: %s from %s", username, r.RemoteAddr)
			sendAuthRequired(w)
			return
		}

		// Authentication successful
		next.ServeHTTP(w, r)
	})
}

// sendAuthRequired sends a 401 Unauthorized response with WWW-Authenticate header
func sendAuthRequired(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="NetUtil File Server"`)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("401 Unauthorized\n"))
}

// loggingMiddleware logs all requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Extract username from basic auth
		username, _, _ := r.BasicAuth()

		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		log.Printf("%s %s %s %d %s %s",
			r.RemoteAddr,
			username,
			r.Method,
			wrapped.statusCode,
			r.URL.Path,
			duration,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// corsMiddleware adds permissive CORS headers for use in isolated network environments.
// This server is intended for local/isolated network use only — do not expose it to the internet.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		// Note: Allow-Credentials is omitted — it cannot be combined with wildcard origin.

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cleanPath ensures the path is clean and doesn't escape workspace
func cleanPath(requestPath string) string {
	// Clean the path to remove .. and . elements
	cleaned := filepath.Clean("/" + requestPath)

	// Ensure it starts with /
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	return cleaned
}
