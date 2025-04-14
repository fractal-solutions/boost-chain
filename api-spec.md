# Boost Chain API Specification

## System Overview
The Boost Chain system consists of multiple services running on different ports:
- Main Blockchain (2222)
- Smart Contract Service (2223)
- Metadata Service (2224)
- User Management Service (2225)

## Authentication
All protected endpoints require a JWT token in the Authorization header:
```bash
Authorization: Bearer <your-jwt-token>
```

## Service Endpoints

### 1. User Management Service (Port 2225)

#### Register New User
```bash
POST http://localhost:2225/register
Content-Type: application/json

{
    "username": "user1",
    "phoneNumber": "+1234567890",
    "password": "securepass123",
    "role": "USER"  // Optional, defaults to "USER"
}
```
Response:
```json
{
    "success": true,
    "message": "User created successfully",
    "data": {
        "id": "user_id",
        "username": "user1",
        "publicKey": "user_public_key",
        "privateKey": "user_private_key",
        "token": "jwt_token"
    }
}
```

#### Login
```bash
POST http://localhost:2225/login
Content-Type: application/json

{
    "phoneNumber": "+1234567890",
    "password": "securepass123"
}
```

### 2. Main Blockchain Service (Port 2222)

#### Create Transaction
```bash
POST http://localhost:2222/txn
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "from": "sender_public_key",
    "to": "recipient_public_key",
    "amount": 100,
    "type": "TRANSFER"
}
```

#### Deposit
```bash
POST http://localhost:2222/deposit
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "to": "recipient_public_key",
    "amount": 1000
}
```

#### Withdraw
```bash
POST http://localhost:2222/withdraw
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "from": "user_public_key",
    "amount": 500
}
```

### 3. Smart Contract Service (Port 2223)

#### Create Contract
```bash
POST http://localhost:2223/contract
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "creator": "creator_public_key",
    "participants": ["participant_public_key"],
    "amount": 100,
    "interval": 604800000,  // 1 week in milliseconds
    "endDate": "2024-06-26T00:00:00.000Z",
    "terms": {
        "paymentMethod": "BOOST",
        "penalties": {
            "lateFee": 10
        }
    }
}
```

#### Get Contract Details
```bash
GET http://localhost:2223/contract/:contractId
Authorization: Bearer <jwt_token>
```

#### Get Contract Payments
```bash
GET http://localhost:2223/contract/:contractId/payments
Authorization: Bearer <jwt_token>
```

#### Get Contract Status
```bash
GET http://localhost:2223/contract/:contractId/status
Authorization: Bearer <jwt_token>
```

### 4. Metadata Service (Port 2224)

#### Get Balance
```bash
POST http://localhost:2224/balance
Content-Type: application/json

{
    "address": "user_public_key"
}
```

#### Get Transaction History
```bash
POST http://localhost:2224/history
Content-Type: application/json

{
    "address": "user_public_key"
}
```

#### Get Last Transactions
```bash
POST http://localhost:2224/last-transactions
Content-Type: application/json

{
    "address": "user_public_key",
    "limit": 5
}
```

#### Get Address Statistics
```bash
POST http://localhost:2224/stats
Content-Type: application/json

{
    "address": "user_public_key"
}
```

#### Get Active Addresses
```bash
GET http://localhost:2224/active-addresses?minBalance=100&limit=10
```

## Role-Based Access Control

### Available Roles
1. ADMIN
2. SME
3. USER
4. VALIDATOR

### Role Permissions

#### ADMIN
- manage_users
- view_all_transactions
- manage_nodes
- deposit
- withdraw
- transfer
- view_chain

#### SME
- transfer
- deposit
- withdraw
- view_own_transactions
- view_chain
- create_contracts

#### USER
- transfer
- view_own_transactions
- participate_in_contracts

#### VALIDATOR
- validate_transactions
- view_chain
- view_all_transactions

## Error Handling

All endpoints return errors in the following format:
```json
{
    "success": false,
    "error": "Error message description"
}
```

Common HTTP Status Codes:
- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 500: Internal Server Error

## Rate Limiting
- API requests are limited to 100 requests per minute per IP
- Smart contract operations are limited to 10 per minute per user
- Failed authentication attempts are limited to 5 per 15 minutes

## Best Practices
1. Always store private keys securely
2. Use HTTPS in production
3. Implement proper error handling
4. Include appropriate headers in all requests
5. Handle token expiration and renewal
6. Monitor transaction status
7. Implement proper logging
8. Use appropriate role permissions

## Example Integration Flow

1. Register a user
2. Login to get JWT token
3. Use token for authenticated requests
4. Create transactions or smart contracts
5. Monitor transaction/contract status
6. Handle responses appropriately

## Development Setup
```bash
# Start all services
bun run boost-chain.js    # Port 2222
bun run boost-smartcron.js # Port 2223
bun run boost-metadata.js  # Port 2224
bun run boost-users.js     # Port 2225
```