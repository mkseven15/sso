package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// LoggingInterceptor logs all gRPC requests
func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		// Log request
		log.Printf("→ gRPC %s started", info.FullMethod)

		// Call handler
		resp, err := handler(ctx, req)

		// Log response
		duration := time.Since(start)
		if err != nil {
			log.Printf("← gRPC %s failed: %v (took %v)", info.FullMethod, err, duration)
		} else {
			log.Printf("← gRPC %s succeeded (took %v)", info.FullMethod, duration)
		}

		return resp, err
	}
}

// RecoveryInterceptor recovers from panics in gRPC handlers
func RecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("🚨 Panic recovered in %s: %v\n%s", info.FullMethod, r, debug.Stack())
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

// Rate limiter implementation
type rateLimiter struct {
	mu       sync.Mutex
	requests map[string]*requestCounter
}

type requestCounter struct {
	count     int
	resetTime time.Time
}

var (
	limiter = &rateLimiter{
		requests: make(map[string]*requestCounter),
	}
	maxRequestsPerMinute = 100
)

// RateLimitInterceptor implements rate limiting
func RateLimitInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Extract IP from metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return handler(ctx, req)
		}

		var clientIP string
		if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
			clientIP = ips[0]
		} else if ips := md.Get("x-real-ip"); len(ips) > 0 {
			clientIP = ips[0]
		}

		if clientIP == "" {
			return handler(ctx, req)
		}

		// Check rate limit
		if !limiter.allow(clientIP) {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, exists := rl.requests[key]

	if !exists || now.After(counter.resetTime) {
		// New window
		rl.requests[key] = &requestCounter{
			count:     1,
			resetTime: now.Add(1 * time.Minute),
		}
		return true
	}

	if counter.count >= maxRequestsPerMinute {
		return false
	}

	counter.count++
	return true
}

// Clean up old entries periodically
func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			limiter.cleanup()
		}
	}()
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, counter := range rl.requests {
		if now.After(counter.resetTime) {
			delete(rl.requests, key)
		}
	}
}

// CustomErrorHandler handles errors from gRPC-Gateway
func CustomErrorHandler(
	ctx context.Context,
	mux *runtime.ServeMux,
	marshaler runtime.Marshaler,
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	// Convert gRPC error to HTTP status
	st := status.Convert(err)
	httpStatus := runtime.HTTPStatusFromCode(st.Code())

	// Custom error response
	errorResponse := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    st.Code().String(),
			"message": st.Message(),
		},
	}

	// Add details if available
	if len(st.Details()) > 0 {
		details := make([]interface{}, len(st.Details()))
		for i, detail := range st.Details() {
			details[i] = detail
		}
		errorResponse["error"].(map[string]interface{})["details"] = details
	}

	// Set headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	// Write response
	json.NewEncoder(w).Encode(errorResponse)

	// Log error
	log.Printf("❌ HTTP %d: %s - %s", httpStatus, r.Method, r.URL.Path)
}

// ExtractMetadata extracts metadata from HTTP headers
func ExtractMetadata(ctx context.Context, req *http.Request) metadata.MD {
	md := metadata.New(map[string]string{})

	// Extract important headers
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		md.Set("x-forwarded-for", ip)
	}
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		md.Set("x-real-ip", ip)
	}
	if ua := req.Header.Get("User-Agent"); ua != "" {
		md.Set("user-agent", ua)
	}
	if auth := req.Header.Get("Authorization"); auth != "" {
		md.Set("authorization", auth)
	}

	return md
}

// AuthenticationMiddleware validates JWT tokens (for HTTP)
func AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for certain paths
		if r.URL.Path == "/health" || r.URL.Path == "/api/v1/auth/login" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Token validation would happen here
		// For now, pass through to gRPC layer for validation

		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware adds CORS headers
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin || allowedOrigin == "*" {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Request-ID")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// Handle preflight
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersMiddleware adds security headers
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		next.ServeHTTP(w, r)
	})
}
