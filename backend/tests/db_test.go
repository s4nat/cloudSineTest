package tests

import (
	"database/sql"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"os"
	"testing"
)

func init() {
	// Load .env file if it exists
	if err := godotenv.Load("../.env"); err != nil {
		log.Printf("No .env file found or error loading it: %v", err)
		// Not returning error as env vars might be set in other ways (e.g., in CI/CD)
	}
}

func TestDatabaseConnection(t *testing.T) {
	// Check if DATABASE_URL is set
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Fatal("DATABASE_URL environment variable not set")
	}

	// Try to connect to the database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to open database connection: %v", err)
	}
	defer db.Close()

	// Test the connection
	err = db.Ping()
	if err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	// Test creating a table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS test_table (
			id SERIAL PRIMARY KEY,
			name TEXT NOT NULL
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	// Test inserting data
	_, err = db.Exec("INSERT INTO test_table (name) VALUES ($1)", "test_name")
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	// Test querying data
	var name string
	err = db.QueryRow("SELECT name FROM test_table WHERE name = $1", "test_name").Scan(&name)
	if err != nil {
		t.Fatalf("Failed to query test data: %v", err)
	}
	if name != "test_name" {
		t.Errorf("Expected name to be 'test_name', got '%s'", name)
	}

	// Clean up
	_, err = db.Exec("DROP TABLE test_table")
	if err != nil {
		t.Fatalf("Failed to clean up test table: %v", err)
	}
}
