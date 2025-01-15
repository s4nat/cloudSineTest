// main.go
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type User struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type FileMetadata struct {
	ID         int64          `json:"id"`
	UserID     int64          `json:"user_id"`
	FileName   string         `json:"file_name"`
	FileType   string         `json:"file_type"`
	FileSize   int64          `json:"file_size"`
	Status     string         `json:"status"`
	Threat     sql.NullString `json:"threat"`
	AnalysisID sql.NullString `json:"analysis_id"`
	Sha256Hash sql.NullString `json:"sha256_hash"`
	Analysis   sql.NullString `json:"analysis"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

type App struct {
	Router      *mux.Router
	DB          *sql.DB
	OAuthConfig *oauth2.Config
	JWTSecret   []byte
}

// Custom type for context key
type contextKey string

const userIDKey contextKey = "userID"

func (app *App) Initialize() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize database connection
	connStr := os.Getenv("DATABASE_URL")
	if !strings.Contains(connStr, "sslmode=") {
		connStr += "?sslmode=disable" // For development
		// Or use "?sslmode=require" for production with SSL
	}

	app.DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	// Test the connection
	err = app.DB.Ping()
	if err != nil {
		log.Fatal("Database connection error:", err)
	}

	// Initialize OAuth configuration
	app.OAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	app.JWTSecret = []byte(os.Getenv("JWT_SECRET"))
	app.Router = mux.NewRouter()
	app.Router.Use(corsMiddleware)
	app.setupRoutes()
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers for all responses
		w.Header().Set("Access-Control-Allow-Origin", os.Getenv("FRONTEND_URL"))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Process other requests
		next.ServeHTTP(w, r)
	})
}

func (app *App) setupRoutes() {
	// Apply CORS middleware globally
	app.Router.Use(corsMiddleware)

	// Auth routes
	authRouter := app.Router.PathPrefix("/api/auth").Subrouter()
	authRouter.HandleFunc("/google", app.handleGoogleAuth).Methods("POST", "OPTIONS")
	authRouter.HandleFunc("/refresh", app.handleTokenRefresh).Methods("POST", "OPTIONS")

	// File routes (protected)
	fileRoutes := app.Router.PathPrefix("/api/files").Subrouter()
	fileRoutes.Use(app.authMiddleware)
	fileRoutes.HandleFunc("/upload", app.handleFileUpload).Methods("POST", "OPTIONS")
	fileRoutes.HandleFunc("", app.handleListFiles).Methods("GET", "OPTIONS")
	fileRoutes.HandleFunc("/{id}", app.handleGetFile).Methods("GET", "OPTIONS")
	fileRoutes.HandleFunc("/{id}/scan-results", app.handleGetScanResults).Methods("GET", "OPTIONS")
}

// Custom MarshalJSON to handle the null fields
func (f FileMetadata) MarshalJSON() ([]byte, error) {
	type Alias FileMetadata // prevent recursion

	return json.Marshal(&struct {
		*Alias
		Threat       *string `json:"threat"`
		VirusTotalID *string `json:"analysis_id"`
		Analysis     *string `json:"analysis"`
	}{
		Alias:        (*Alias)(&f),
		Threat:       nullStringToPtr(f.Threat),
		VirusTotalID: nullStringToPtr(f.AnalysisID),
		Analysis:     nullStringToPtr(f.Analysis),
	})
}

// Helper function to convert sql.NullString to *string
func nullStringToPtr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	return &s.String
}

func calculateSHA256(file multipart.File) (string, error) {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Authentication handlers
func (app *App) handleGoogleAuth(w http.ResponseWriter, r *http.Request) {
	var authData struct {
		Credential string `json:"credential"`
		Email      string `json:"email"`
		Name       string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&authData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user User
	err := app.DB.QueryRow(
		"INSERT INTO users (name, email) VALUES ($1, $2) "+
			"ON CONFLICT (email) DO UPDATE SET name = $1 "+
			"RETURNING id, name, email, created_at",
		authData.Name, authData.Email,
	).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if err != nil {
		log.Printf("Database error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Generate JWT
	jwtToken, err := app.generateJWT(user)
	if err != nil {
		log.Printf("JWT generation error: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := struct {
		Token string `json:"token"`
		User  struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"user"`
	}{
		Token: jwtToken,
		User: struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}{
			ID:    user.ID,
			Email: user.Email,
			Name:  user.Name,
		},
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}

func (app *App) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	// Implementation of token refresh logic
}

// File handlers
func (app *App) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	// Get userID from context (set by auth middleware)
	userID := r.Context().Value(userIDKey).(int64)

	// Parse multipart form
	err := r.ParseMultipartForm(10 << 20) // 10 MB limit
	if err != nil {
		log.Printf("Form parsing error: %v", err)
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("File retrieval error: %v", err)
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Calculate SHA256 hash
	fileHash, err := calculateSHA256(file)
	if err != nil {
		http.Error(w, "Error calculating file hash", http.StatusInternalServerError)
		return
	}

	// Check if file already exists
	var existingFile FileMetadata
	err = app.DB.QueryRow(
		"SELECT id, file_name, status, analysis_id FROM file_metadata WHERE sha256_hash = $1",
		fileHash,
	).Scan(&existingFile.ID, &existingFile.FileName, &existingFile.Status, &existingFile.AnalysisID)

	if err == nil {
		// File exists, return it with a special status code
		w.WriteHeader(http.StatusConflict) // 409 Conflict
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "File already exists",
			"file":    existingFile,
		})
		return
	} else if err != sql.ErrNoRows {
		// Unexpected database error
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Rewind file for VirusTotal upload
	file.Seek(0, 0)

	// Create multipart form for VirusTotal API
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", header.Filename)
	if err != nil {
		log.Printf("Form creation error: %v", err)
		http.Error(w, "Error creating form", http.StatusInternalServerError)
		return
	}

	// Copy uploaded file to the form
	if _, err := io.Copy(part, file); err != nil {
		log.Printf("File copy error: %v", err)
		http.Error(w, "Error copying file", http.StatusInternalServerError)
		return
	}
	writer.Close()

	// Send to VirusTotal API
	req, err := http.NewRequest("POST", "https://www.virustotal.com/api/v3/files", body)
	if err != nil {
		log.Printf("VirusTotal request creation error: %v", err)
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", writer.FormDataContentType())
	req.Header.Add("x-apikey", os.Getenv("VIRUSTOTAL_API_KEY"))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("VirusTotal API error: %v", err)
		http.Error(w, "Error sending request to VirusTotal", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Parse VirusTotal response
	var vtResponse struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vtResponse); err != nil {
		log.Printf("VirusTotal response parsing error: %v", err)
		http.Error(w, "Error parsing VirusTotal response", http.StatusInternalServerError)
		return
	}

	// Create FileMetadata with nullable fields
	var metadata FileMetadata
	metadata.UserID = userID
	metadata.FileName = header.Filename
	metadata.FileType = header.Header.Get("Content-Type")
	metadata.FileSize = header.Size
	metadata.Status = "Scanning"

	// Set up nullable fields
	metadata.AnalysisID = sql.NullString{
		String: vtResponse.Data.ID,
		Valid:  vtResponse.Data.ID != "",
	}
	metadata.Sha256Hash = sql.NullString{
		String: fileHash,
		Valid:  fileHash != "",
	}
	metadata.Threat = sql.NullString{
		String: "",
		Valid:  false,
	}
	metadata.Analysis = sql.NullString{
		String: "",
		Valid:  false,
	}

	// Insert into database
	err = app.DB.QueryRow(
		`INSERT INTO file_metadata 
        (user_id, file_name, file_type, file_size, status, analysis_id, sha256_hash, threat, analysis) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, created_at, updated_at`,
		metadata.UserID,
		metadata.FileName,
		metadata.FileType,
		metadata.FileSize,
		metadata.Status,
		metadata.AnalysisID,
		metadata.Sha256Hash,
		metadata.Threat,
		metadata.Analysis,
	).Scan(
		&metadata.ID,
		&metadata.CreatedAt,
		&metadata.UpdatedAt,
	)

	if err != nil {
		log.Printf("Database insertion error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")

	// Encode and send response
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.Printf("Response encoding error: %v", err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}

func (app *App) handleListFiles(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int64)

	rows, err := app.DB.Query(
		`SELECT 
            id, 
            user_id, 
            file_name, 
            file_type, 
            file_size, 
            status, 
            threat, 
            analysis_id, 
            analysis, 
            created_at, 
            updated_at 
        FROM file_metadata 
        WHERE user_id = $1 
        ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		log.Printf("Database query error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var files []FileMetadata
	for rows.Next() {
		var file FileMetadata
		err := rows.Scan(
			&file.ID,
			&file.UserID,
			&file.FileName,
			&file.FileType,
			&file.FileSize,
			&file.Status,
			&file.Threat,
			&file.AnalysisID,
			&file.Analysis,
			&file.CreatedAt,
			&file.UpdatedAt,
		)
		if err != nil {
			log.Printf("Row scan error: %v", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		files = append(files, file)
	}

	if err = rows.Err(); err != nil {
		log.Printf("Row iteration error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(files); err != nil {
		log.Printf("JSON encoding error: %v", err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}

// Add this function to handle getting a single file's details
func (app *App) handleGetFile(w http.ResponseWriter, r *http.Request) {
	// Get file ID from URL parameters
	vars := mux.Vars(r)
	fileID := vars["id"]

	// Get userID from context (set by auth middleware)
	userID := r.Context().Value(userIDKey).(int64)

	// Query the database for the file
	var file FileMetadata
	err := app.DB.QueryRow(
		`SELECT id, user_id, file_name, file_type, file_size, status, 
         threat, analysis_id, sha256_hash, analysis, created_at, updated_at 
         FROM file_metadata 
         WHERE id = $1 AND user_id = $2`,
		fileID, userID,
	).Scan(
		&file.ID, &file.UserID, &file.FileName, &file.FileType,
		&file.FileSize, &file.Status, &file.Threat, &file.AnalysisID,
		&file.Sha256Hash, &file.Analysis, &file.CreatedAt, &file.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("Database error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(file)
}

func (app *App) handleGetScanResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

	// Get Analysis ID from database
	var analysisID string
	err := app.DB.QueryRow(
		"SELECT analysis_id FROM file_metadata WHERE id = $1",
		fileID,
	).Scan(&analysisID)
	if err != nil {
		log.Printf("Error getting analysis_id: %v", err)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Get analysis from VirusTotal
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", analysisID),
		nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("accept", "application/json")
	req.Header.Add("x-apikey", os.Getenv("VIRUSTOTAL_API_KEY"))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error calling VirusTotal API: %v", err)
		http.Error(w, "Error getting results from VirusTotal", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var analysis map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		log.Printf("Error decoding VirusTotal response: %v", err)
		http.Error(w, "Error parsing VirusTotal response", http.StatusInternalServerError)
		return
	}

	// Convert analysis to JSON string
	analysisJSON, err := json.Marshal(analysis)
	if err != nil {
		log.Printf("Error marshaling analysis to JSON: %v", err)
		http.Error(w, "Error processing analysis data", http.StatusInternalServerError)
		return
	}

	// Update database with complete status and analysis
	_, err = app.DB.Exec(
		"UPDATE file_metadata SET status = $1, analysis = $2::jsonb WHERE id = $3",
		"Complete",
		string(analysisJSON),
		fileID,
	)
	if err != nil {
		log.Printf("Error updating database: %v", err)
		http.Error(w, "Error updating database", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(analysis)
}

// Middleware
func (app *App) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			log.Println("Missing authorization header")
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		// Remove 'Bearer ' prefix if present
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return app.JWTSecret, nil
		})

		if err != nil {
			log.Printf("Token parsing error: %v", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			log.Println("Invalid token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		userID := int64(claims["user_id"].(float64))

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper functions
func (app *App) generateJWT(user User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString(app.JWTSecret)
}

func main() {
	app := &App{}
	app.Initialize()
	log.Fatal(http.ListenAndServe(":8080", app.Router))
}
