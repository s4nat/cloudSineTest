package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"mime/multipart"
	"net/http"
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

func TestVirusTotalIntegration(t *testing.T) {
	// Skip if running in CI without API key
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		t.Skip("Skipping VirusTotal integration test: VIRUSTOTAL_API_KEY not set")
	}

	// Create a test file
	fileContents := []byte("test file content for virus scanning")
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	part.Write(fileContents)
	writer.Close()

	// Send to VirusTotal API
	req, err := http.NewRequest("POST", "https://www.virustotal.com/api/v3/files", body)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", writer.FormDataContentType())
	req.Header.Add("x-apikey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK; got %v", resp.Status)
	}

	// Parse response to get analysis ID
	var vtResponse struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vtResponse); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if vtResponse.Data.ID == "" {
		t.Fatal("No analysis ID received from VirusTotal")
	}

	// Test getting analysis results
	analysisID := vtResponse.Data.ID
	req, err = http.NewRequest("GET",
		fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", analysisID),
		nil)
	if err != nil {
		t.Fatalf("Failed to create analysis request: %v", err)
	}

	req.Header.Set("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to get analysis: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK for analysis request; got %v", resp.Status)
	}

	var analysis map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		t.Fatalf("Failed to decode analysis response: %v", err)
	}

	// Just verify we got a response with the expected structure
	if analysis["data"] == nil {
		t.Error("Response missing 'data' field")
	}
}
