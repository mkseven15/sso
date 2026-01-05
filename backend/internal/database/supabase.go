package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// User represents a user in the system
type User struct {
	ID                  string
	Username            string
	Email               string
	PasswordHash        string
	FirstName           string
	LastName            string
	IsActive            bool
	Roles               []string
	FailedLoginAttempts int
	LockedUntil         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Session represents an active user session
type Session struct {
	ID           string
	UserID       string
	RefreshToken string
	IPAddress    string
	UserAgent    string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// Supabase represents the database connection
type Supabase struct {
	db *sql.DB
}

// NewSupabase creates a new Supabase connection
func NewSupabase(url, key string) (*Supabase, error) {
	// Parse Supabase URL to get PostgreSQL connection string
	// Format: postgresql://postgres:[PASSWORD]@[PROJECT_REF].supabase.co:5432/postgres
	connStr := fmt.Sprintf("%s?sslmode=require", url)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Supabase{db: db}, nil
}

// Close closes the database connection
func (s *Supabase) Close() error {
	return s.db.Close()
}

// User operations

func (s *Supabase) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, 
		       is_active, failed_login_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE username = $1 AND deleted_at IS NULL
	`

	user := &User{}
	var lockedUntil sql.NullTime

	err := s.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.IsActive,
		&user.FailedLoginAttempts, &lockedUntil,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}

	// Get user roles
	roles, err := s.getUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	user.Roles = roles

	return user, nil
}

func (s *Supabase) GetUserByID(ctx context.Context, userID string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, 
		       is_active, failed_login_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`

	user := &User{}
	var lockedUntil sql.NullTime

	err := s.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.IsActive,
		&user.FailedLoginAttempts, &lockedUntil,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}

	// Get user roles
	roles, err := s.getUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	user.Roles = roles

	return user, nil
}

func (s *Supabase) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, 
		       is_active, failed_login_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL
	`

	user := &User{}
	var lockedUntil sql.NullTime

	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.IsActive,
		&user.FailedLoginAttempts, &lockedUntil,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}

	// Get user roles
	roles, err := s.getUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	user.Roles = roles

	return user, nil
}

func (s *Supabase) UsernameExists(ctx context.Context, username string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND deleted_at IS NULL)`

	var exists bool
	err := s.db.QueryRowContext(ctx, query, username).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check username: %w", err)
	}

	return exists, nil
}

func (s *Supabase) UpdateFailedLoginAttempts(ctx context.Context, userID string, attempts int) error {
	query := `
		UPDATE users
		SET failed_login_attempts = $1, updated_at = NOW()
		WHERE id = $2
	`

	_, err := s.db.ExecContext(ctx, query, attempts, userID)
	if err != nil {
		return fmt.Errorf("failed to update login attempts: %w", err)
	}

	return nil
}

func (s *Supabase) LockAccount(ctx context.Context, userID string, until time.Time) error {
	query := `
		UPDATE users
		SET locked_until = $1, updated_at = NOW()
		WHERE id = $2
	`

	_, err := s.db.ExecContext(ctx, query, until, userID)
	if err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	return nil
}

func (s *Supabase) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	query := `
		UPDATE users
		SET password_hash = $1, failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
		WHERE id = $2
	`

	_, err := s.db.ExecContext(ctx, query, passwordHash, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// Session operations

func (s *Supabase) StoreSession(ctx context.Context, session *Session) error {
	query := `
		INSERT INTO sessions (user_id, refresh_token, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := s.db.ExecContext(ctx, query,
		session.UserID, session.RefreshToken, session.IPAddress,
		session.UserAgent, session.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}

	return nil
}

func (s *Supabase) GetSessionByRefreshToken(ctx context.Context, token string) (*Session, error) {
	query := `
		SELECT id, user_id, refresh_token, ip_address, user_agent, expires_at, created_at
		FROM sessions
		WHERE refresh_token = $1
	`

	session := &Session{}
	err := s.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID, &session.UserID, &session.RefreshToken,
		&session.IPAddress, &session.UserAgent,
		&session.ExpiresAt, &session.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}

func (s *Supabase) UpdateSessionToken(ctx context.Context, sessionID, newToken string) error {
	query := `
		UPDATE sessions
		SET refresh_token = $1
		WHERE id = $2
	`

	_, err := s.db.ExecContext(ctx, query, newToken, sessionID)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

func (s *Supabase) DeleteUserSessions(ctx context.Context, userID string) error {
	query := `DELETE FROM sessions WHERE user_id = $1`

	_, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete sessions: %w", err)
	}

	return nil
}

// Password reset operations

func (s *Supabase) StoreResetToken(ctx context.Context, userID, token string) error {
	query := `
		INSERT INTO password_resets (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		SET token = $2, expires_at = $3, created_at = NOW()
	`

	expiresAt := time.Now().Add(1 * time.Hour)
	_, err := s.db.ExecContext(ctx, query, userID, token, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to store reset token: %w", err)
	}

	return nil
}

func (s *Supabase) VerifyResetToken(ctx context.Context, userID, token string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM password_resets
			WHERE user_id = $1 AND token = $2 AND expires_at > NOW()
		)
	`

	var valid bool
	err := s.db.QueryRowContext(ctx, query, userID, token).Scan(&valid)
	if err != nil {
		return false, fmt.Errorf("failed to verify reset token: %w", err)
	}

	return valid, nil
}

func (s *Supabase) DeleteResetToken(ctx context.Context, userID string) error {
	query := `DELETE FROM password_resets WHERE user_id = $1`

	_, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete reset token: %w", err)
	}

	return nil
}

// Helper functions

func (s *Supabase) getUserRoles(ctx context.Context, userID string) ([]string, error) {
	query := `
		SELECT r.name
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	// Default role if none assigned
	if len(roles) == 0 {
		roles = []string{"user"}
	}

	return roles, nil
}
