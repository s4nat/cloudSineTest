module virus-scan-app

go 1.23.4

require (
	github.com/golang-jwt/jwt/v4 v4.5.1
	github.com/gorilla/mux v1.8.1
	github.com/joho/godotenv v1.5.1
	github.com/lib/pq v1.10.9
	golang.org/x/oauth2 v0.25.0
)

require cloud.google.com/go/compute/metadata v0.3.0 // indirect