// backend/tests/build_test.go
package tests

import (
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"log"
	"os"
	"testing"
)

type TestApp struct {
	Router    *mux.Router
	JWTSecret []byte
}

func init() {
	// Load .env file if it exists
	if err := godotenv.Load("../.env"); err != nil {
		log.Printf("No .env file found or error loading it: %v", err)
		// Not returning error as env vars might be set in other ways (e.g., in CI/CD)
	}
}

func TestRequiredEnvironmentVariables(t *testing.T) {
	requiredEnvVars := []string{
		"JWT_SECRET",
		"VIRUSTOTAL_API_KEY",
		"DATABASE_URL",
	}

	for _, env := range requiredEnvVars {
		if os.Getenv(env) == "" {
			t.Errorf("Required environment variable %s not set", env)
		}
	}
}

func TestAppInitialization(t *testing.T) {
	app := &TestApp{}

	// Test router initialization
	app.Router = mux.NewRouter()
	if app.Router == nil {
		t.Error("Failed to initialize router")
	}

	// Test JWT secret initialization
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		t.Error("JWT_SECRET not set")
	}
	app.JWTSecret = []byte(jwtSecret)
	if len(app.JWTSecret) == 0 {
		t.Error("Failed to initialize JWT secret")
	}
}
