package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"

	"github.com/mkseven15/sso/internal/auth"
	"github.com/mkseven15/sso/internal/database"
	"github.com/mkseven15/sso/internal/middleware"
	authpb "github.com/mkseven15/sso/proto/auth"
)

const (
	defaultGRPCPort = "9090"
	defaultHTTPPort = "8080"
)

type Server struct {
	grpcServer *grpc.Server
	httpServer *http.Server
	db         *database.Supabase
	config     *Config
}

type Config struct {
	GRPCPort       string
	HTTPPort       string
	SupabaseURL    string
	SupabaseKey    string
	JWTSecret      string
	SAMLCertPath   string
	SAMLKeyPath    string
	AllowedOrigins []string
}

func main() {
	log.Println("🚀 Starting MkSeven1 SSO Identity Provider...")

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  No .env file found, relying on system environment variables")
	}

	// Load configuration
	config := loadConfig()

	// Initialize server
	server, err := newServer(config)
	if err != nil {
		log.Fatalf("❌ Failed to create server: %v", err)
	}

	// Start servers in goroutines
	errChan := make(chan error, 2)

	// Start gRPC server
	go func() {
		log.Printf("✅ Starting gRPC server on port %s", config.GRPCPort)
		if err := server.startGRPC(); err != nil {
			errChan <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	// Start HTTP/gRPC-Gateway server
	go func() {
		log.Printf("✅ Starting HTTP server on port %s", config.HTTPPort)
		if err := server.startHTTP(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	log.Println("🎉 MkSeven1 SSO is running!")
	log.Printf("   - gRPC: localhost:%s", config.GRPCPort)
	log.Printf("   - HTTP: localhost:%s", config.HTTPPort)
	log.Println("   - Health: http://localhost:" + config.HTTPPort + "/health")

	// Wait for shutdown signal
	gracefulShutdown(server, errChan)
}

// loadConfig loads configuration from environment variables
func loadConfig() *Config {
	return &Config{
		GRPCPort:     getEnv("GRPC_PORT", defaultGRPCPort),
		HTTPPort:     getEnv("HTTP_PORT", defaultHTTPPort),
		SupabaseURL:  getEnvRequired("SUPABASE_URL"),
		SupabaseKey:  getEnvRequired("SUPABASE_KEY"),
		JWTSecret:    getEnvRequired("JWT_SECRET"),
		SAMLCertPath: getEnv("SAML_CERT_PATH", "./certs/saml.crt"),
		SAMLKeyPath:  getEnv("SAML_KEY_PATH", "./certs/saml.key"),
		AllowedOrigins: []string{
			getEnv("ALLOWED_ORIGIN", "https://mkseven1.com"),
		},
	}
}

// newServer creates a new server instance
func newServer(config *Config) (*Server, error) {
	// Initialize database connection
	db, err := database.NewSupabase(config.SupabaseURL, config.SupabaseKey)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Create auth service
	authService := auth.NewAuthService(db, config.JWTSecret, config.SAMLCertPath, config.SAMLKeyPath)

	// Create gRPC server with interceptors
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			middleware.LoggingInterceptor(),
			middleware.RecoveryInterceptor(),
			middleware.RateLimitInterceptor(),
		),
	)

	// Register auth service
	authpb.RegisterAuthServiceServer(grpcServer, authService)

	// Enable reflection for debugging (disable in production)
	reflection.Register(grpcServer)

	return &Server{
		grpcServer: grpcServer,
		db:         db,
		config:     config,
	}, nil
}

// startGRPC starts the gRPC server
func (s *Server) startGRPC() error {
	listener, err := net.Listen("tcp", ":"+s.config.GRPCPort)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	return s.grpcServer.Serve(listener)
}

// startHTTP starts the HTTP server with gRPC-Gateway
func (s *Server) startHTTP() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create gRPC-Gateway mux
	mux := runtime.NewServeMux(
		runtime.WithErrorHandler(middleware.CustomErrorHandler),
		runtime.WithMetadata(middleware.ExtractMetadata),
	)

	// Register gRPC-Gateway endpoints
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err := authpb.RegisterAuthServiceHandlerFromEndpoint(
		ctx,
		mux,
		"localhost:"+s.config.GRPCPort,
		opts,
	)
	if err != nil {
		return fmt.Errorf("failed to register gateway: %w", err)
	}

	// Create HTTP router
	handler := s.setupHTTPHandler(mux)

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         ":" + s.config.HTTPPort,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s.httpServer.ListenAndServe()
}

// setupHTTPHandler sets up the HTTP handler with middleware
func (s *Server) setupHTTPHandler(gatewayMux http.Handler) http.Handler {
	// Create main mux
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","service":"mkseven1-sso"}`)
	})

	// API endpoints (gRPC-Gateway)
	mux.Handle("/api/", gatewayMux)

	// Static files (frontend)
	fs := http.FileServer(http.Dir("./frontend"))
	mux.Handle("/", fs)

	// Setup CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   s.config.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})

	return corsHandler.Handler(mux)
}

// gracefulShutdown handles graceful shutdown
func gracefulShutdown(server *Server, errChan chan error) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		log.Printf("❌ Server error: %v", err)
	case sig := <-quit:
		log.Printf("🛑 Received signal: %v", sig)
	}

	log.Println("🔄 Shutting down servers...")

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if server.httpServer != nil {
		if err := server.httpServer.Shutdown(ctx); err != nil {
			log.Printf("⚠️  HTTP server shutdown error: %v", err)
		} else {
			log.Println("✅ HTTP server stopped")
		}
	}

	// Stop gRPC server
	if server.grpcServer != nil {
		server.grpcServer.GracefulStop()
		log.Println("✅ gRPC server stopped")
	}

	// Close database connection
	if server.db != nil {
		if err := server.db.Close(); err != nil {
			log.Printf("⚠️  Database close error: %v", err)
		} else {
			log.Println("✅ Database connection closed")
		}
	}

	log.Println("👋 Shutdown complete")
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvRequired(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("❌ Required environment variable %s is not set", key)
	}
	return value
}
