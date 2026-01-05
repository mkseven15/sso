# MkSeven1 SSO Identity Provider

A production-ready, secure Single Sign-On (SSO) Identity Provider built with Go, gRPC, and React. Integrates seamlessly with Google Workspace using SAML 2.0.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![Status](https://img.shields.io/badge/status-production-success)

## 🚀 Features

- **Modern Authentication**: JWT-based authentication with access and refresh tokens
- **Google Workspace Integration**: SAML 2.0 SSO for seamless Google Workspace login
- **High Performance**: Built with Go and gRPC for maximum performance
- **Secure by Default**: bcrypt password hashing, rate limiting, account lockout
- **Production Ready**: Comprehensive error handling, logging, and monitoring
- **Easy Deployment**: One-command deployment to AWS EC2
- **Beautiful UI**: Clean, responsive login interface
- **Database**: PostgreSQL via Supabase with automatic connection pooling

## 📋 Architecture

```
┌─────────────┐     HTTPS      ┌─────────────┐     gRPC      ┌─────────────┐
│   Browser   │ ◄──────────────► │    Nginx    │ ◄────────────► │  Go Backend │
│  (Frontend) │                 │ (Reverse    │               │   (gRPC)    │
└─────────────┘                 │   Proxy)    │               └─────────────┘
                                └─────────────┘                       │
                                                                     │
                                ┌─────────────┐                     │
                                │   Google    │ ◄───SAML 2.0────────┤
                                │  Workspace  │                     │
                                └─────────────┘                     │
                                                                     │
                                                              ┌──────▼──────┐
                                                              │  Supabase   │
                                                              │  (Postgres) │
                                                              └─────────────┘
```

## 🛠️ Tech Stack

### Frontend
- HTML5, CSS3, Vanilla JavaScript
- Responsive design with modern UI/UX
- No framework dependencies (lightweight)

### Backend
- **Go 1.21+**: Main programming language
- **gRPC**: High-performance RPC framework
- **grpc-gateway**: RESTful API gateway
- **JWT**: Token-based authentication
- **bcrypt**: Password hashing
- **Protocol Buffers**: API contract definition

### Database
- **PostgreSQL**: Via Supabase
- **Supabase**: BaaS with built-in auth helpers and storage

### Infrastructure
- **AWS EC2**: Ubuntu 22.04 LTS
- **Nginx**: Reverse proxy and SSL termination
- **Let's Encrypt**: Free SSL certificates
- **Systemd**: Service management

## 📦 Installation

### Prerequisites

- Go 1.21 or higher
- Protocol Buffer Compiler (protoc)
- PostgreSQL database (Supabase recommended)
- AWS account (for deployment)
- Domain name with DNS control
- Google Workspace admin access

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/mkseven1-sso.git
cd mkseven1-sso

# Setup backend
cd backend
cp .env.example .env
# Edit .env with your credentials

# Install dependencies
go mod download

# Generate proto files
make proto

# Build
make build

# Run locally
make run
```

Visit `http://localhost:8080` to see the login page.

## 🚀 Deployment

See [SETUP_GUIDE.md](SETUP_GUIDE.md) for complete deployment instructions.

### Quick Deploy to EC2

```bash
# SSH into your EC2 instance
ssh -i your-key.pem ubuntu@your-ec2-ip

# Clone and setup
git clone https://github.com/yourusername/mkseven1-sso.git
cd mkseven1-sso/deployment/scripts
chmod +x install.sh
sudo ./install.sh

# Configure environment
cd ../../backend
nano .env  # Add your credentials

# Start service
sudo systemctl start mkseven1-sso
sudo systemctl enable mkseven1-sso
```

## 🔧 Configuration

### Environment Variables

```bash
# Database
SUPABASE_URL=postgresql://postgres:password@db.xxxxx.supabase.co:5432/postgres
SUPABASE_KEY=your-supabase-anon-key

# JWT
JWT_SECRET=your-super-secret-key-min-32-characters

# Server
GRPC_PORT=9090
HTTP_PORT=8080

# SAML
SAML_CERT_PATH=./certs/saml.crt
SAML_KEY_PATH=./certs/saml.key

# CORS
ALLOWED_ORIGIN=https://sso.mkseven1.com
```

### Database Schema

The database uses the following tables:
- `users`: User accounts and credentials
- `sessions`: Active user sessions with refresh tokens
- `password_resets`: Password reset tokens
- `roles`: User roles (admin, user, etc.)
- `user_roles`: User-to-role mappings

## 🔐 Security Features

- **Password Security**: bcrypt with cost factor 12
- **JWT Tokens**: Signed with HS256, short-lived access tokens (15 min)
- **Refresh Tokens**: Long-lived (7 days) for token renewal
- **Rate Limiting**: 100 requests/minute per IP
- **Account Lockout**: 5 failed attempts = 15-minute lockout
- **HTTPS Only**: All traffic encrypted with TLS 1.3
- **CORS Protection**: Configurable allowed origins
- **SQL Injection Protection**: Prepared statements
- **XSS Protection**: Security headers and input validation

## 📊 API Endpoints

### Authentication

- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Refresh access token
- `GET /api/v1/auth/validate` - Validate token
- `POST /api/v1/auth/logout` - User logout

### Password Recovery

- `POST /api/v1/auth/forgot-username` - Recover username
- `POST /api/v1/auth/forgot-password` - Initiate password reset
- `POST /api/v1/auth/reset-password` - Complete password reset

### SAML (Google Workspace)

- `POST /api/v1/auth/saml/assertion` - Generate SAML assertion

### User Management

- `POST /api/v1/auth/check-username` - Check if username exists
- `GET /api/v1/auth/user` - Get user information

See [API_DOCS.md](docs/API_DOCS.md) for detailed API documentation.

## 🧪 Testing

```bash
# Run all tests
cd backend
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/auth

# Benchmark tests
go test -bench=. ./...
```

## 📝 Development

### Project Structure

```
mkseven1-sso/
├── frontend/              # Frontend application
│   ├── index.html        # Login page
│   ├── css/              # Stylesheets
│   ├── js/               # JavaScript
│   └── assets/           # Images, fonts
├── backend/              # Backend application
│   ├── cmd/server/       # Main entry point
│   ├── internal/         # Private application code
│   │   ├── auth/         # Authentication logic
│   │   ├── database/     # Database layer
│   │   └── middleware/   # Middleware
│   ├── proto/            # Protocol buffer definitions
│   └── pkg/              # Public libraries
├── deployment/           # Deployment scripts
├── certs/               # SSL certificates
└── config/              # Configuration files
```

### Adding New Features

1. Define new RPC in `proto/auth/auth.proto`
2. Run `make proto` to generate code
3. Implement handler in `internal/auth/handler.go`
4. Add database methods in `internal/database/supabase.go`
5. Update frontend to call new endpoint
6. Write tests
7. Update documentation

## 📚 Documentation

- [Setup Guide](SETUP_GUIDE.md) - Complete deployment instructions
- [API Documentation](docs/API_DOCS.md) - API reference
- [Architecture](docs/ARCHITECTURE.md) - System architecture
- [Contributing](CONTRIBUTING.md) - How to contribute
- [Changelog](CHANGELOG.md) - Version history

## 🐛 Troubleshooting

### Service won't start

```bash
# Check service status
sudo systemctl status mkseven1-sso

# View logs
sudo journalctl -u mkseven1-sso -f

# Check if ports are available
sudo netstat -tulpn | grep -E '8080|9090'
```

### Database connection fails

```bash
# Test connection manually
psql "your-supabase-connection-string"

# Check if Supabase project is running
curl https://your-project-ref.supabase.co/rest/v1/
```

### Google SSO not working

1. Verify SAML certificate is correctly uploaded
2. Check URLs match exactly (including https://)
3. Review Google Workspace admin audit logs
4. Ensure domain is verified in Google Workspace

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **MkSeven1 Team** - *Initial work*

## 🙏 Acknowledgments

- Google for Protocol Buffers and gRPC
- Supabase for database infrastructure
- The Go community for excellent libraries
- Let's Encrypt for free SSL certificates

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/mkseven1-sso/issues)
- **Email**: support@mkseven1.com
- **Discord**: [Join our Discord](#)

## 🗺️ Roadmap

- [ ] Multi-factor authentication (TOTP)
- [ ] OAuth 2.0 provider support
- [ ] Admin dashboard for user management
- [ ] Audit logging and compliance reports
- [ ] Docker containerization
- [ ] Kubernetes deployment support
- [ ] Social login providers (GitHub, Microsoft)
- [ ] WebAuthn/FIDO2 support

---

Made with ❤️ by MkSeven1 Team
