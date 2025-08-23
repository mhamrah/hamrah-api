# WebAuthn API Endpoints

✅ **IMPLEMENTED** - WebAuthn endpoints have been successfully implemented in hamrah-api to complete the migration of WebAuthn operations from the web layer.

## Implemented Endpoints

### 1. Begin Registration
**POST** `/api/webauthn/register/begin`
- **Purpose**: Generate registration options for new users
- **Auth**: Public endpoint (no token required)
- **Body**: 
  ```json
  {
    "email": "user@example.com",
    "name": "User Name"
  }
  ```
- **Response**:
  ```json
  {
    "success": true,
    "options": {
      "challenge": "base64-encoded-challenge",
      "rp": { "name": "Hamrah", "id": "hamrah.app" },
      "user": { "id": "base64-encoded-id", "name": "User", "displayName": "User" },
      "pubKeyCredParams": [...],
      "timeout": 60000,
      "attestation": "direct",
      "challengeId": "uuid-for-tracking"
    }
  }
  ```

### 2. Complete Registration
**POST** `/api/webauthn/register/complete`
- **Purpose**: Verify registration response and create credential
- **Auth**: Public endpoint (no token required)
- **Body**:
  ```json
  {
    "challengeId": "uuid-from-begin",
    "response": {
      "id": "credential-id",
      "rawId": "base64-credential-id", 
      "response": {
        "attestationObject": "base64-attestation",
        "clientDataJSON": "base64-client-data"
      },
      "type": "public-key"
    },
    "email": "user@example.com",
    "name": "User Name"
  }
  ```
- **Response**: Same as `/api/internal/users` (creates user + session)

### 3. Begin Authentication
**POST** `/api/webauthn/authenticate/begin`
- **Purpose**: Generate authentication options for existing users
- **Auth**: Public endpoint (no token required)
- **Body**:
  ```json
  {
    "email": "user@example.com" // Optional for resident keys
  }
  ```
- **Response**:
  ```json
  {
    "success": true,
    "options": {
      "challenge": "base64-encoded-challenge",
      "timeout": 60000,
      "rpId": "hamrah.app",
      "allowCredentials": [...],
      "userVerification": "preferred",
      "challengeId": "uuid-for-tracking"
    }
  }
  ```

### 4. Complete Authentication
**POST** `/api/webauthn/authenticate/complete`
- **Purpose**: Verify authentication response and create session
- **Auth**: Public endpoint (no token required)
- **Body**:
  ```json
  {
    "challengeId": "uuid-from-begin",
    "response": {
      "id": "credential-id",
      "rawId": "base64-credential-id",
      "response": {
        "authenticatorData": "base64-auth-data",
        "clientDataJSON": "base64-client-data",
        "signature": "base64-signature",
        "userHandle": "base64-user-handle"
      },
      "type": "public-key"
    }
  }
  ```
- **Response**: Same as `/api/internal/sessions` (creates session)

### 5. Get User Credentials
**GET** `/api/webauthn/credentials`
- **Purpose**: List user's registered passkeys
- **Auth**: Bearer token required
- **Response**:
  ```json
  {
    "success": true,
    "credentials": [
      {
        "id": "credential-id",
        "name": "Device Name",
        "createdAt": "2025-01-01T00:00:00Z",
        "lastUsed": "2025-01-02T00:00:00Z"
      }
    ]
  }
  ```

### 6. Delete Credential
**DELETE** `/api/webauthn/credentials/{credentialId}`
- **Purpose**: Remove a specific passkey
- **Auth**: Bearer token required
- **Response**: `{ "success": true }`

### 7. Update Credential Name
**PATCH** `/api/webauthn/credentials/{credentialId}`
- **Purpose**: Rename a passkey
- **Auth**: Bearer token required
- **Body**: `{ "name": "New Device Name" }`
- **Response**: `{ "success": true }`

## Database Schema Requirements

### webauthn_credentials table
```sql
CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    device_type TEXT,
    backed_up BOOLEAN DEFAULT FALSE,
    transports TEXT, -- JSON array of transport methods
    name TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_credential_id (credential_id)
);
```

### webauthn_challenges table  
```sql
CREATE TABLE webauthn_challenges (
    id TEXT PRIMARY KEY,
    challenge TEXT NOT NULL,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    email TEXT,
    type TEXT NOT NULL CHECK (type IN ('registration', 'authentication')),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_expires_at (expires_at)
);
```

## Security Considerations

1. **Challenge Expiry**: Challenges should expire after 5 minutes
2. **Rate Limiting**: Implement rate limiting on begin endpoints
3. **App Attestation**: iOS requests should include attestation headers
4. **Origin Validation**: Verify RP ID matches request origin
5. **Counter Validation**: Ensure authenticator counter always increases
6. **Cleanup**: Periodically clean expired challenges

## Implementation Status

✅ **COMPLETED** - All endpoints have been implemented in `src/handlers/webauthn.rs`:

1. ✅ **Begin/Complete Registration & Authentication** - Core WebAuthn flows implemented
2. ✅ **List/Delete Credentials** - Credential management endpoints  
3. ✅ **Update Credential Names** - Passkey renaming functionality

## Integration Notes

- All endpoints are integrated into the main Axum router in `src/lib.rs`
- Database schema is implemented in the initial migration
- Security considerations have been implemented including challenge expiry and proper error handling
- Compatible with existing web layer implementation for seamless migration