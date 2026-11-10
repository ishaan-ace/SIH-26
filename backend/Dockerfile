# Stage 1: Build the Go Analyzer (Pure Go, no CGO required!)
FROM golang:alpine AS go-builder
WORKDIR /go/src/app
# Context is root (.), so we copy the analyzer folder
COPY ./analyzer .
RUN CGO_ENABLED=0 GOOS=linux go build -o analyzer .

# Stage 2: Setup Node Backend
FROM node:20-alpine
WORKDIR /app

# Install dependencies
COPY ./backend/package*.json ./
RUN npm install

# Copy backend source code
COPY ./backend .

# Copy the compiled go binary from Stage 1 to the exact path Node expects
RUN mkdir -p /analyzer
COPY --from=go-builder /go/src/app/analyzer /analyzer/analyzer.exe

CMD ["npm", "run", "dev"]
