package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mkseven15/sso/internal/database"
)

// TokenType represents the type of JWT token
type TokenType string

const (
	AccessTokenType  TokenType = "access"
	RefreshTokenType TokenType = "refresh"
	ResetTokenType   TokenType = "reset"
)

// CustomClaims represents JWT custom claims
type CustomClaims struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Roles     []string  `json:"roles"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token generation and validation
type JWTManager struct {
	secretKey       []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secretKey string, accessTTL, refreshTTL time.Duration) *JWTManager {
	return &JWTManager{
		secretKey:       []byte(secretKey),
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}
}

// GenerateAccessToken generates a new access token
func (m *JWTManager) GenerateAccessToken(user *database.User) (string, error) {
	now := time.Now()
	claims := CustomClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Roles:     user.Roles,
		TokenType: AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "mkseven1-sso",
			Audience:  jwt.ClaimStrings{"mkseven1-services"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// GenerateRefreshToken generates a new refresh token
func (m *JWTManager) GenerateRefreshToken(user *database.User) (string, error) {
	now := time.Now()
	claims := CustomClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		TokenType: RefreshTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.refreshTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "mkseven1-sso",
			Audience:  jwt.ClaimStrings{"mkseven1-services"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// GenerateResetToken generates a password reset token
func (m *JWTManager) GenerateResetToken(user *database.User) (string, error) {
	now := time.Now()
	claims := CustomClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		TokenType: ResetTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)), // 1 hour validity
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "mkseven1-sso",
			Audience:  jwt.ClaimStrings{"mkseven1-password-reset"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// ValidateAccessToken validates an access token and returns claims
func (m *JWTManager) ValidateAccessToken(tokenString string) (*CustomClaims, error) {
	return m.validateToken(tokenString, AccessTokenType)
}

// ValidateRefreshToken validates a refresh token and returns claims
func (m *JWTManager) ValidateRefreshToken(tokenString string) (*CustomClaims, error) {
	return m.validateToken(tokenString, RefreshTokenType)
}

// ValidateResetToken validates a password reset token and returns claims
func (m *JWTManager) ValidateResetToken(tokenString string) (*CustomClaims, error) {
	return m.validateToken(tokenString, ResetTokenType)
}

// validateToken validates any token and checks its type
func (m *JWTManager) validateToken(tokenString string, expectedType TokenType) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("invalid signing method")
			}
			return m.secretKey, nil
		},
	)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Verify token type
	if claims.TokenType != expectedType {
		return nil, errors.New("invalid token type")
	}

	// Verify token is not expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token expired")
	}

	// Verify token is already valid (NotBefore check)
	if claims.NotBefore != nil && claims.NotBefore.After(time.Now()) {
		return nil, errors.New("token not yet valid")
	}

	return claims, nil
}

// ExtractClaims extracts claims without validation (use carefully)
func (m *JWTManager) ExtractClaims(tokenString string) (*CustomClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &CustomClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// RevokeToken adds a token to the revocation list (implement with Redis/Database)
func (m *JWTManager) RevokeToken(tokenString string) error {
	// TODO: Implement token revocation with Redis or database
	// Store token ID or JTI in a blacklist until expiration
	return nil
}

// IsTokenRevoked checks if a token has been revoked
func (m *JWTManager) IsTokenRevoked(tokenString string) (bool, error) {
	// TODO: Implement token revocation check with Redis or database
	return false, nil
}
