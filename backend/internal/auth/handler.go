package auth

import (
	"context"
	"errors"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/mkseven15/sso/internal/database"
	authpb "github.com/mkseven15/sso/proto/auth"
)

const (
	maxLoginAttempts = 5
	lockoutDuration  = 15 * time.Minute
	accessTokenTTL   = 15 * time.Minute
	refreshTokenTTL  = 7 * 24 * time.Hour
)

// AuthService implements the AuthServiceServer interface
type AuthService struct {
	authpb.UnimplementedAuthServiceServer
	db           *database.Supabase
	jwtManager   *JWTManager
	samlProvider *SAMLProvider
}

// NewAuthService creates a new authentication service
func NewAuthService(db *database.Supabase, jwtSecret, samlCertPath, samlKeyPath string) *AuthService {
	jwtManager := NewJWTManager(jwtSecret, accessTokenTTL, refreshTokenTTL)
	samlProvider := NewSAMLProvider(samlCertPath, samlKeyPath)

	return &AuthService{
		db:           db,
		jwtManager:   jwtManager,
		samlProvider: samlProvider,
	}
}

// Login authenticates a user and returns JWT tokens
func (s *AuthService) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	log.Printf("📝 Login attempt for user: %s", req.Username)

	// Validate input
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password are required")
	}

	// Get user from database
	user, err := s.db.GetUserByUsername(ctx, req.Username)
	if err != nil {
		log.Printf("❌ User not found: %s", req.Username)
		return nil, status.Error(codes.NotFound, "invalid credentials")
	}

	// Check if account is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		log.Printf("🔒 Account locked: %s until %v", req.Username, user.LockedUntil)
		return nil, status.Errorf(codes.PermissionDenied,
			"account locked due to too many failed attempts. Try again after %v",
			user.LockedUntil.Format(time.RFC3339))
	}

	// Check if account is active
	if !user.IsActive {
		log.Printf("⛔ Inactive account: %s", req.Username)
		return nil, status.Error(codes.PermissionDenied, "account is inactive")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		log.Printf("❌ Invalid password for user: %s", req.Username)

		// Increment failed login attempts
		failedAttempts := user.FailedLoginAttempts + 1
		if err := s.db.UpdateFailedLoginAttempts(ctx, user.ID, failedAttempts); err != nil {
			log.Printf("⚠️  Failed to update login attempts: %v", err)
		}

		// Lock account if too many failures
		if failedAttempts >= maxLoginAttempts {
			lockUntil := time.Now().Add(lockoutDuration)
			if err := s.db.LockAccount(ctx, user.ID, lockUntil); err != nil {
				log.Printf("⚠️  Failed to lock account: %v", err)
			}
			return nil, status.Error(codes.PermissionDenied,
				"too many failed login attempts. Account locked for 15 minutes")
		}

		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Reset failed login attempts on successful login
	if user.FailedLoginAttempts > 0 {
		if err := s.db.UpdateFailedLoginAttempts(ctx, user.ID, 0); err != nil {
			log.Printf("⚠️  Failed to reset login attempts: %v", err)
		}
	}

	// Generate JWT tokens
	accessToken, err := s.jwtManager.GenerateAccessToken(user)
	if err != nil {
		log.Printf("❌ Failed to generate access token: %v", err)
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user)
	if err != nil {
		log.Printf("❌ Failed to generate refresh token: %v", err)
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	// Store refresh token in database
	if err := s.db.StoreSession(ctx, &database.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		IPAddress:    req.IpAddress,
		UserAgent:    req.UserAgent,
		ExpiresAt:    time.Now().Add(refreshTokenTTL),
	}); err != nil {
		log.Printf("⚠️  Failed to store session: %v", err)
		// Non-critical, continue
	}

	// Generate SAML assertion for Google Workspace
	samlResponse, err := s.samlProvider.GenerateAssertion(user)
	if err != nil {
		log.Printf("⚠️  Failed to generate SAML assertion: %v", err)
		// Non-critical for basic login
	}

	log.Printf("✅ Login successful for user: %s", req.Username)

	return &authpb.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
		TokenType:    "Bearer",
		User:         convertUserToProto(user),
		SamlResponse: samlResponse,
	}, nil
}

// RefreshToken issues a new access token using a refresh token
func (s *AuthService) RefreshToken(ctx context.Context, req *authpb.RefreshTokenRequest) (*authpb.RefreshTokenResponse, error) {
	log.Println("🔄 Token refresh request")

	// Validate refresh token
	claims, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		log.Printf("❌ Invalid refresh token: %v", err)
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	// Check if session exists and is valid
	session, err := s.db.GetSessionByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		log.Printf("❌ Session not found: %v", err)
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}

	if session.ExpiresAt.Before(time.Now()) {
		log.Println("❌ Session expired")
		return nil, status.Error(codes.Unauthenticated, "session expired")
	}

	// Get user
	user, err := s.db.GetUserByID(ctx, claims.UserID)
	if err != nil {
		log.Printf("❌ User not found: %v", err)
		return nil, status.Error(codes.NotFound, "user not found")
	}

	if !user.IsActive {
		log.Printf("⛔ Inactive account: %s", user.Username)
		return nil, status.Error(codes.PermissionDenied, "account is inactive")
	}

	// Generate new tokens
	newAccessToken, err := s.jwtManager.GenerateAccessToken(user)
	if err != nil {
		log.Printf("❌ Failed to generate access token: %v", err)
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user)
	if err != nil {
		log.Printf("❌ Failed to generate refresh token: %v", err)
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	// Update session with new refresh token
	if err := s.db.UpdateSessionToken(ctx, session.ID, newRefreshToken); err != nil {
		log.Printf("⚠️  Failed to update session: %v", err)
	}

	log.Println("✅ Token refreshed successfully")

	return &authpb.RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
	}, nil
}

// ValidateToken checks if a token is valid
func (s *AuthService) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	claims, err := s.jwtManager.ValidateAccessToken(req.Token)
	if err != nil {
		return &authpb.ValidateTokenResponse{Valid: false}, nil
	}

	user, err := s.db.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return &authpb.ValidateTokenResponse{Valid: false}, nil
	}

	return &authpb.ValidateTokenResponse{
		Valid:     true,
		User:      convertUserToProto(user),
		ExpiresAt: timestamppb.New(claims.ExpiresAt.Time), // Fixed: Access .Time from NumericDate
	}, nil
}

// Logout invalidates the current session
func (s *AuthService) Logout(ctx context.Context, req *authpb.LogoutRequest) (*authpb.LogoutResponse, error) {
	log.Println("👋 Logout request")

	claims, err := s.jwtManager.ValidateAccessToken(req.Token)
	if err != nil {
		// Even if token is invalid, consider logout successful
		return &authpb.LogoutResponse{Success: true, Message: "logged out"}, nil
	}

	// Delete all sessions for this user
	if err := s.db.DeleteUserSessions(ctx, claims.UserID); err != nil {
		log.Printf("⚠️  Failed to delete sessions: %v", err)
	}

	log.Println("✅ Logout successful")

	return &authpb.LogoutResponse{Success: true, Message: "logged out successfully"}, nil
}

// CheckUsername verifies if a username exists
func (s *AuthService) CheckUsername(ctx context.Context, req *authpb.CheckUsernameRequest) (*authpb.CheckUsernameResponse, error) {
	exists, err := s.db.UsernameExists(ctx, req.Username)
	if err != nil {
		log.Printf("⚠️  Error checking username: %v", err)
		return &authpb.CheckUsernameResponse{Exists: false}, nil
	}

	return &authpb.CheckUsernameResponse{Exists: exists}, nil
}

// ForgotUsername sends username recovery email
func (s *AuthService) ForgotUsername(ctx context.Context, req *authpb.ForgotUsernameRequest) (*authpb.ForgotUsernameResponse, error) {
	log.Printf("📧 Username recovery request for email: %s", req.Email)

	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Don't reveal if email exists
		return &authpb.ForgotUsernameResponse{
			Success: true,
			Message: "if email exists, username has been sent",
		}, nil
	}

	// Send email with username
	if err := s.sendUsernameEmail(user.Email, user.Username); err != nil {
		log.Printf("⚠️  Failed to send email: %v", err)
	}

	return &authpb.ForgotUsernameResponse{
		Success: true,
		Message: "if email exists, username has been sent",
	}, nil
}

// ForgotPassword initiates password reset flow
func (s *AuthService) ForgotPassword(ctx context.Context, req *authpb.ForgotPasswordRequest) (*authpb.ForgotPasswordResponse, error) {
	log.Printf("🔑 Password reset request for user: %s", req.Username)

	user, err := s.db.GetUserByUsername(ctx, req.Username)
	if err != nil || user.Email != req.Email {
		// Don't reveal if user exists or email matches
		return &authpb.ForgotPasswordResponse{
			Success: true,
			Message: "if information matches, reset link has been sent",
		}, nil
	}

	// Generate reset token
	resetToken, err := s.jwtManager.GenerateResetToken(user)
	if err != nil {
		log.Printf("❌ Failed to generate reset token: %v", err)
		return nil, status.Error(codes.Internal, "failed to generate reset token")
	}

	// Store reset token
	if err := s.db.StoreResetToken(ctx, user.ID, resetToken); err != nil {
		log.Printf("⚠️  Failed to store reset token: %v", err)
	}

	// Send email with reset link
	if err := s.sendPasswordResetEmail(user.Email, resetToken); err != nil {
		log.Printf("⚠️  Failed to send email: %v", err)
	}

	return &authpb.ForgotPasswordResponse{
		Success: true,
		Message: "if information matches, reset link has been sent",
	}, nil
}

// ResetPassword completes password reset with token
func (s *AuthService) ResetPassword(ctx context.Context, req *authpb.ResetPasswordRequest) (*authpb.ResetPasswordResponse, error) {
	log.Println("🔐 Password reset confirmation")

	// Validate reset token
	claims, err := s.jwtManager.ValidateResetToken(req.ResetToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired reset token")
	}

	// Verify token exists in database
	valid, err := s.db.VerifyResetToken(ctx, claims.UserID, req.ResetToken)
	if err != nil || !valid {
		return nil, status.Error(codes.Unauthenticated, "invalid reset token")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password")
	}

	// Update password
	if err := s.db.UpdatePassword(ctx, claims.UserID, string(hashedPassword)); err != nil {
		return nil, status.Error(codes.Internal, "failed to update password")
	}

	// Delete reset token
	if err := s.db.DeleteResetToken(ctx, claims.UserID); err != nil {
		log.Printf("⚠️  Failed to delete reset token: %v", err)
	}

	// Invalidate all sessions
	if err := s.db.DeleteUserSessions(ctx, claims.UserID); err != nil {
		log.Printf("⚠️  Failed to invalidate sessions: %v", err)
	}

	log.Println("✅ Password reset successful")

	return &authpb.ResetPasswordResponse{
		Success: true,
		Message: "password reset successfully",
	}, nil
}

// GetSAMLAssertion generates SAML assertion for Google Workspace
func (s *AuthService) GetSAMLAssertion(ctx context.Context, req *authpb.SAMLAssertionRequest) (*authpb.SAMLAssertionResponse, error) {
	user, err := s.db.GetUserByID(ctx, req.UserId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	samlResponse, err := s.samlProvider.GenerateAssertion(user)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate SAML assertion")
	}

	return &authpb.SAMLAssertionResponse{
		SamlResponse: samlResponse,
		RelayState:   req.RelayState,
	}, nil
}

// GetUserInfo retrieves authenticated user information
func (s *AuthService) GetUserInfo(ctx context.Context, req *authpb.GetUserInfoRequest) (*authpb.GetUserInfoResponse, error) {
	user, err := s.db.GetUserByID(ctx, req.UserId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &authpb.GetUserInfoResponse{
		User: convertUserToProto(user),
	}, nil
}

// Helper functions

func convertUserToProto(user *database.User) *authpb.User {
	return &authpb.User{
		Id:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		IsActive:  user.IsActive,
		Roles:     user.Roles,
		CreatedAt: timestamppb.New(user.CreatedAt),
		UpdatedAt: timestamppb.New(user.UpdatedAt),
	}
}

func (s *AuthService) sendUsernameEmail(email, username string) error {
	// TODO: Implement email sending
	log.Printf("📧 Would send username to: %s", email)
	return nil
}

func (s *AuthService) sendPasswordResetEmail(email, token string) error {
	// TODO: Implement email sending
	log.Printf("📧 Would send reset link to: %s", email)
	return nil
}

// ValidatePasswordStrength ensures password meets security requirements
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	// Add more validation as needed
	return nil
}