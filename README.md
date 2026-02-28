# Auth as a Service (AaaS)

A production-ready authentication service with multi-application support, OAuth 2.0, and 2FA/MFA capabilities.

Auth as a Service is a comprehensive authentication microservice that allows multiple applications to integrate secure user authentication through a centralized API. Built with Node.js, TypeScript, PostgreSQL and Redis, it provides enterprise-grade security features including multi-factor authentication, OAuth integration, and granular access control.

## Features

### Authentication
- 🔐 Email/Password authentication with secure password hashing (bcrypt)
- 🔄 JWT-based access & refresh tokens
- 🚪 Session management with database persistence
- 🔑 Password reset flow via email
- 🛡️ Rate limiting on authentication endpoints

### Multi-Factor Authentication (2FA/MFA)
- 📱 TOTP-based 2FA with Google Authenticator
- 📊 QR code generation for easy setup
- 🔢 6-digit code verification
- 💾 10 backup codes (hashed) for account recovery
- ⚡ Two-step login process

### OAuth 2.0
- 🌐 Google OAuth integration (Authorization Code Flow)
- 🔗 Seamless integration with existing session system
- 🎫 Access & refresh token management

### Multi-Application Architecture
- 🏢 Support for multiple client applications
- 🔑 API Key authentication per application
- 👥 Granular user access control (UserAppAccess)
- 🌍 CORS configuration per application
- 🎚️ Application activation/deactivation
- 🔄 API Key regeneration

### Security & Compliance
- 🔒 Token blacklisting (Redis)
- 📝 Comprehensive audit logging (Winston)
- 🚫 Session limits per user
- 🛡️ Request validation (express-validator)
- 🔐 Encrypted sensitive data
- ⏱️ Configurable token expiration

### Developer Experience
- 📘 TypeScript for type safety
- 🗄️ Prisma ORM with PostgreSQL
- 🔄 Redis for caching & session management
- 🎯 Clean architecture (Services, Controllers, Middlewares)
- 📋 Centralized error handling
- 🔍 Environment variable validation at startup

## Tech & Stack

### Backend
- Node.js ^20.x - Runtime environment
- TypeScript ^5.x - Type-safe JavaScript
- Express.js ^5.x - Web framework

### Database & ORM
- PostgreSQL ^16.x - Primary database
- Prisma ^7.x - Type-safe ORM
- Redis ^7.x - Caching & token blacklist

### Authentication & Security
- jsonwebtoken ^9.x - Token-based authentication
- bcrypt ^6.x - Password hashing
- Passport.js ^0.7.x - OAuth strategies
- passport-google-oauth20 ^2.x - Google OAuth strategy
- speakeasy ^2.x - TOTP/2FA generation
- qrcode ^1.x - QR code generation

### Validation & Logging
- express-validator ^7.x - Request validation
- Winston ^3.x - Logging system
- express-rate-limit ^8.x - Rate limiting

### Email
- Nodemailer ^6.x - Email service

### Development Tools
- ts-node ^10.x - TypeScript execution
- dotenv ^17.x - Environment configuration

## Architectures

### System Overview

```
            ┌───────────────────────────────────────────────────────────────┐
            │                     Client Applications                       │
            │        (Client_App A, Client_App B, Mobile App, etc.)         │
            └────────────┬────────────────────────────────┬─────────────────┘
                         │      x-api-key: app_abc123     │
                         │                                │
                         ▼                                ▼
            ┌───────────────────────────────────────────────────────────────┐
            │                   Auth as a Service API                       │
            │                                                               │
            │     ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
            │     │   Auth       │  │    OAuth     │  │     2FA      │      │
            │     │  (Login,     │  │   (Google)   │  │   (TOTP,     │      │
            │     │  Register)   │  │              │  │   Backup)    │      │
            │     └──────────────┘  └──────────────┘  └──────────────┘      │
            │                                                               │
            │     ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
            │     │ Application  │  │   Sessions   │  │  Validation  │      │
            │     │ Management   │  │  & Tokens    │  │ & Security   │      │
            │     └──────────────┘  └──────────────┘  └──────────────┘      │
            └─────────┬────────────────────┬─────────────────────┬──────────┘
                      │                    │                     │
                      ▼                    ▼                     ▼
            ┌──────────────────┐  ┌──────────────────┐  ┌───────────────────┐
            │   PostgreSQL     │  │      Redis       │  │   Google OAuth    │
            │  (Users, Apps,   │  │  (Cache, Token   │  │                   │
            │    Sessions)     │  │    Blacklist)    |  │                   │
            └──────────────────┘  └──────────────────┘  └───────────────────┘
```

### Authentication Flow
1. Client requests login with credentials + x-api-key
2. verifyApplication middleware validates API Key
3. AuthService verifies credentials
4. Check if user has access to the application
5. If 2FA enabled → Return temp token
6. User submits 2FA code
7. Generate JWT access + refresh tokens
8. Store session in PostgreSQL
9. Return tokens to client

### Multi-Application Architecture
Each client application:

- Has a unique API Key
- Defines allowed origins (CORS)
- Manages its own user access list
- Can be activated/deactivated independently

## Installation

### Prerequisites
- Node.js >= 20.x
- PostgreSQL >= 16.x
- Redis >= 7.x
- npm or yarn

### 1 - Clone the repository
```
git clone https://github.com/patrick-rakotoharilalao/auth-service-project.git
cd auth-as-a-service
```
### 2 - Install dependencies
```
npm install
```

### 3 - Set up environment variables
Copy the example environment file and configure it:
```
cp .env.example .env
```
Edit .env with your configuration.

### 4 - Set up the database
```
# Generate Prisma client
npx prisma generate

# Run migrations
npx prisma migrate dev

# Populate the database with default admin user and test application
npx prisma db seed
```
**Default credentials:**
- Email: `admin@auth.com`
- Password: `Admin.auth`
- Role: ADMIN

**Default application:**
- Name: Default Application
- Allowed Origins: `http://localhost:3000`, `http://localhost:3001`
- API Key: Generated automatically (displayed after seeding)

> **Note:** Run this command after running migrations to set up your development environment.

### 5 - Make sure Redis and PostgreSql are started

### 6 - Run the application
```
# Development mode
npm run dev
```
The API will be available at http://localhost:3001
