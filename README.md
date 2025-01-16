# cloudSineTest
# VirusScanner Project Documentation

## Table of Contents
- [Overview](#overview)
- [Frontend Architecture](#frontend-architecture)
- [Backend Architecture](#backend-architecture)
- [Nginx Configuration](#nginx-configuration)
- [Database Setup](#database-setup)
- [Docker Configuration](#docker-configuration)
- [CI/CD Pipeline](#cicd-pipeline)

## Overview

The VirusScanner project is a web application that allows users to upload files and scan them for potential security threats using the VirusTotal API. The application is built using React for the frontend, Go for the backend, and uses PostgreSQL for data storage.

## Frontend Architecture

### Components

#### Authentication
- `LoginPage.jsx`: Handles Google SSO authentication
- `ProtectedRoute.jsx`: Route wrapper for authenticated routes

#### Layout
- `MainLayout.jsx`: Main application layout with sidebar and header
- `Header.jsx`: Top navigation bar with user info and logout
- `Sidebar.jsx`: Navigation sidebar with upload and files links

#### File Management
- `FileUpload.jsx`: Handles file upload with drag-and-drop functionality
- `FileList.jsx`: Displays list of uploaded files
- `FileDetails.jsx`: Shows detailed scan results for individual files

### Custom Hooks

- `useAuth.js`: Authentication state management
  ```javascript
  const { user, login, logout, isAuthenticated } = useAuth();
  ```

- `useFiles.js`: File management operations
  ```javascript
  const { files, loading, error, fetchFiles, uploadFile, scanFile } = useFiles();
  ```

### Services

- `api.js`: Axios instance configuration with auth interceptors
- `files.js`: File-related API calls
  ```javascript
  fileService.uploadFile(file)
  fileService.getFiles()
  fileService.getFileDetails(fileId)
  fileService.getScanResults(fileId)
  ```

## Backend Architecture

### API Routes

#### Authentication Endpoints
```
POST /api/auth/google - Google SSO authentication
POST /api/auth/refresh - JWT token refresh
```

#### File Management Endpoints
```
POST /api/files/upload - Upload new file
GET /api/files - List all files
GET /api/files/{id} - Get file details
GET /api/files/{id}/scan-results - Get scan results
```

### Handler Functions

#### Authentication Handlers
- `handleGoogleAuth`: Processes Google OAuth authentication
- `handleTokenRefresh`: Refreshes JWT tokens
- `authMiddleware`: Validates JWT tokens

#### File Handlers
- `handleFileUpload`: Processes file uploads and initiates VirusTotal scan
- `handleListFiles`: Retrieves user's files
- `handleGetFile`: Gets single file details
- `handleGetScanResults`: Fetches scan results from VirusTotal

### VirusTotal Integration

The backend integrates with VirusTotal API for file scanning:

1. File Upload Process:
```go
// Calculate file hash
fileHash := calculateSHA256(file)

// Upload to VirusTotal
resp, err := client.Post("https://www.virustotal.com/api/v3/files", ...)

// Store analysis ID
analysisID := vtResponse.Data.ID
```

2. Scan Results Retrieval:
```go
// Get analysis results
resp, err := client.Get(fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", analysisID))
```

## Nginx Configuration

### HTTPS Configuration
```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
}
```

### SSL Termination
- SSL certificates managed at Nginx level
- HTTP traffic redirected to HTTPS
```nginx
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

## Database Setup

### Production (RDS PostgreSQL)
- Instance: db.t3.micro
- Multi-AZ: Disabled (cost optimization)
- Storage: GP2 (General Purpose SSD)
- Backup: Daily automated backups

### Development (Local PostgreSQL)
- Docker container with volume persistence
- Initialized with migration scripts
```yaml
db:
  image: postgres:14-alpine
  volumes:
    - postgres_data:/var/lib/postgresql/data
    - ./backend/db/migrations:/docker-entrypoint-initdb.d
```

## Docker Configuration

### Development

#### Dockerfile.dev (Backend)
```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
RUN go install github.com/cosmtrek/air@latest
CMD ["air"]
```

#### docker-compose.override.yml
```yaml
services:
  nginx:
    volumes:
      - ./frontend:/app
  backend:
    volumes:
      - ./backend:/app
    command: go run main.go
  db:
    image: postgres:14-alpine
```

### Production

#### Dockerfile.prod (Backend)
```dockerfile
FROM golang:1.23.4-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
COPY --from=builder /app/main .
CMD ["./main"]
```

#### docker-compose.prod.yml
```yaml
services:
  nginx:
    image: ${ECR_REGISTRY}/virusscanner-frontend:${IMAGE_TAG}
  backend:
    image: ${ECR_REGISTRY}/virusscanner-backend:${IMAGE_TAG}
```

## CI/CD Pipeline

### GitHub Actions Configuration

#### Jobs

1. Build and Push
```yaml
build-and-push:
  runs-on: ubuntu-latest
  steps:
    - Configure AWS credentials
    - Login to Amazon ECR
    - Build and push Frontend image
    - Build and push Backend image
```

2. Deploy
```yaml
deploy:
  needs: build-and-push
  steps:
    - Configure AWS credentials
    - Setup SSH key
    - Deploy to EC2
```

#### Deployment Process

1. Image Build and Push:
   - Build Docker images for frontend and backend
   - Tag images with Git SHA and 'latest'
   - Push to Amazon ECR

2. EC2 Deployment:
   - SSH into EC2 instance
   - Pull latest images from ECR
   - Update docker-compose environment
   - Restart containers with new images

```bash
ssh ec2-user@$EC2_HOST "cd ~/virusscanner && \
  docker-compose -f docker-compose.yml -f docker-compose.prod.yml pull && \
  docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
```

### Security Considerations

- AWS credentials stored as GitHub secrets
- SSL certificates mounted as read-only volumes
- JWT tokens for API authentication
- CORS configured for specific origins
- File upload size limits enforced at Nginx level
