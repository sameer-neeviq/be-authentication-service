# Authentication Service

A FastAPI-based Backend authentication service that handles OAuth2/OIDC flows with AWS Cognito.

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

## Using boto3 / AWS SDK

This project can use boto3 to call AWS services (for example, Cognito admin
operations). To get started:

1. Install dependencies (boto3 was added to `requirements.txt`):

```bash
pip install -r requirements.txt
```

2. Provide AWS credentials using one of the standard methods:
	- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN`.
	- Shared credentials file: `~/.aws/credentials`.
	- IAM role when running on AWS (EC2, ECS, Lambda, etc.).

3. Example: use the small wrapper in `app/services/aws_client.py` to call
	Cognito's `admin_get_user`:

```python
from app.services.aws_client import AWSClient

client = AWSClient()
resp = client.admin_get_user('some-username')
print(resp)
```

4. The wrapper uses `app/config/settings.py` for region and user pool id. Set
	`COGNITO_REGION` and `COGNITO_USER_POOL_ID` in your `.env` or environment.

Notes:
- boto3 picks up credentials and region automatically from the environment.
- For higher-level AWS functionality consider using `aioboto3` if you need
  async clients.
