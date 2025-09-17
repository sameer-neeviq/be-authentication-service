# Auth BFF - Authentication Service

A FastAPI-based Backend for Frontend (BFF) authentication service that handles OAuth2/OIDC flows with AWS Cognito.

## Features

- **OAuth2/OIDC Authentication**: Complete flow with AWS Cognito
- **PKCE Security**: Proof Key for Code Exchange for enhanced security
- **HTTP-only Cookies**: Secure token storage away from JavaScript
- **Structured Logging**: Comprehensive logging and error handling
- **Type Safety**: Full Pydantic validation and type hints
- **Production Ready**: Docker support, health checks, and monitoring

## Quick Start

### Development
1. **Configure environment**: Copy `.env.example` to `.env` and update values
2. **Run with Docker**: `docker compose up --build`
3. **Access service**: http://localhost:8001

### Local Development
```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

## Configuration

### Cognito Setup
- Set environment variables in `.env` (copy from `.env.example`)
- App client redirect URI must include: `http://localhost:8001/auth/callback`
- Sign-out redirect: `http://localhost:5173/`

### Environment Variables
See `.env.example` for all available configuration options.

## API Endpoints

- **GET /auth/login** - Initiate OAuth2 login flow
- **GET /auth/callback** - Handle OAuth2 callback from Cognito
- **POST /auth/refresh** - Refresh access tokens
- **POST /auth/logout** - Logout and clear cookies
- **GET /auth/me** - Get authentication status
- **GET /health** - Health check endpoint

## Authentication Flow

1. Frontend redirects to `/auth/login`
2. Service generates PKCE pair and redirects to Cognito
3. User authenticates with Cognito
4. Cognito redirects back to `/auth/callback`
5. Service exchanges code for tokens and sets HTTP-only cookies
6. Frontend can now make authenticated requests

## Testing

```bash
pytest tests/
```

## Production Notes

- Set `SECURE_COOKIES=true` for HTTPS environments
- Use Redis or database for state storage (currently in-memory)
- Configure proper CORS origins for your frontend
- Add JWT token validation for enhanced security
