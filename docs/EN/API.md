# 🌀 Araf Protocol: API Documentation

> **Version:** 2.0 | **Base URL:** `/api` | **Last Updated:** March 2026

This document provides a detailed reference for the backend API endpoints of the Araf Protocol.

---

## Authentication

The API uses a two-layer token system for security:

1.  **Auth JWT (JSON Web Token):** A short-lived (15 min) token obtained via the SIWE (Sign-In with Ethereum) flow. **AUDIT FIX F-01:** JWT is now set as an `httpOnly + Secure + SameSite=Strict` cookie named `araf_jwt`. It is inaccessible by JavaScript (XSS protection). It is automatically sent with `credentials: 'include'` in subsequent requests.
2.  **Refresh Token:** A 7-day `araf_refresh` cookie used to obtain a new token pair when the JWT expires. Sent only to `/api/auth/*` endpoints (`path: /api/auth`).
3.  **PII Token:** An even shorter-lived (15 min) and trade-scoped token specifically required to access sensitive PII data like an IBAN. This token is sent via the `Authorization: Bearer <piiToken>` header (not a cookie).

### Auth Flow (SIWE + Cookie)

1.  `GET /auth/nonce?wallet=<address>`: Retrieve a single-use, unique nonce.
2.  **Client-Side:** Sign the EIP-4361 message with the received nonce.
3.  `POST /auth/verify`: Send the message and signature to receive the JWT and Refresh Token as **httpOnly cookies**.
4.  **Subsequent Requests:** Send requests with `credentials: 'include'` — the cookie is added automatically, no manual Authorization header is needed.
5.  `GET /api/auth/me`: Checks if the cookie is valid when the page loads (this endpoint is necessary because an httpOnly cookie cannot be read by JS).
6.  `POST /auth/refresh`: Called to get a new token pair when the JWT expires (on a 401 response). The refresh token is read automatically from the cookie.

---

## Endpoints

### Auth Routes (`/api/auth`)

#### `GET /auth/nonce`
* **Description:** Generates a single-use nonce for the SIWE signature process. Stored in Redis with a 5-minute TTL.
* **Authorization:** Public
* **Query Parameters:** `wallet` (the user's Ethereum wallet address)
* **Success Response (200 OK):**
```json
{
  "nonce": "a1b2c3d4e5f6...",
  "siweDomain": "araf.protocol"
}
```

#### `POST /auth/verify`
* **Description:** Verifies the SIWE signature and, if valid, sets the JWT + Refresh Token as **httpOnly cookies**.
* **Authorization:** Public
* **Request Body:**
```json
{
  "message": "Full SIWE message in EIP-4361 format",
  "signature": "0x..."
}
```
* **Success Response (200 OK):**
```json
{
  "wallet": "0x...",
  "profile": { "wallet_address": "0x...", "reputation_cache": { ... }, "is_banned": false }
}
```
> **AUDIT FIX F-01:** Tokens are **not returned** in the response body. `araf_jwt` (15 min) and `araf_refresh` (7 days, path: /api/auth) are set as httpOnly cookies. Inaccessible from JavaScript.

#### `GET /auth/me`
* **Description:** Returns session information if the JWT in the cookie is valid. The frontend uses this to determine the `isAuthenticated` state on page load. This endpoint is mandatory since httpOnly cookies cannot be read by JS.
* **Authorization:** Auth JWT Cookie (`araf_jwt`)
* **Success Response (200 OK):**
```json
{ "wallet": "0x...", "authenticated": true }
```
* **Error Response (401):** If the cookie is missing or expired.

#### `POST /auth/refresh`
* **Description:** Used to renew an expired JWT. The refresh token is read automatically from the `araf_refresh` cookie.
* **Authorization:** Refresh Token Cookie (`araf_refresh`)
* **Request Body:**
```json
{
  "wallet": "0x..."
}
```
> **AUDIT FIX F-01:** The `refreshToken` field has been removed from the body. It is automatically read from the cookie.
* **Success Response (200 OK):**
```json
{ "wallet": "0x..." }
```
> New `araf_jwt` and `araf_refresh` cookies are set. Tokens are not returned in the body.

#### `POST /auth/logout`
* **Description:** Logs out the user. Deletes the refresh token family records in Redis and clears cookies.
* **Authorization:** Auth JWT Cookie
* **Success Response (200 OK):**
```json
{ "success": true, "message": "Logged out successfully." }
```

#### `PUT /auth/profile`
* **Description:** Updates the user's bank account owner name, IBAN, and Telegram information. Data is encrypted with AES-256-GCM before being written to the database.
* **Authorization:** Auth JWT Cookie
* **Request Body:**
```json
{
  "bankOwner": "John Doe",
  "iban": "TR...",
  "telegram": "your_username"
}
```
* **Success Response (200 OK):**
```json
{ "success": true, "message": "Profile information updated." }
```

---

### Listing Routes (`/api/listings`)

#### `GET /api/listings`
* **Description:** Lists open listings in the marketplace. Supports filtering and pagination.
* **Authorization:** Public
* **Query Parameters:** `fiat`, `amount`, `tier`, `page`, `limit`
* **Success Response (200 OK):**
```json
{
  "listings": [ { "_id": "...", "maker_address": "...", "crypto_asset": "USDT", "fiat_currency": "TRY", "exchange_rate": 33.5, "limits": { "min": 500, "max": 2500 }, "tier_rules": { "required_tier": 1, "maker_bond_pct": 8, "taker_bond_pct": 10 }, "status": "OPEN" } ],
  "total": 15,
  "page": 1,
  "limit": 20
}
```

#### `POST /api/listings`
* **Description:** Creates a new P2P listing. The maker's on-chain tier is validated.
* **Authorization:** Auth JWT Cookie
* **Request Body:**
```json
{
  "crypto_asset": "USDT",
  "fiat_currency": "TRY",
  "exchange_rate": 33.50,
  "limits": { "min": 500, "max": 2500 },
  "tier": 1,
  "token_address": "0x..."
}
```
> **Note:** The flat `tier` field must be sent, not `tier_rules`. `token_address` is required.
* **Success Response (201 Created):** Returns the full object of the created listing.

#### `DELETE /api/listings/:id`
* **Description:** Removes a listing from the marketplace (soft delete). On-chain escrow cancellation is handled separately via the `cancelOpenEscrow()` contract function.
* **Authorization:** Auth JWT Cookie (Only the listing owner can delete)
* **Success Response (200 OK):**
```json
{ "success": true }
```
* **Error Responses:** `403 Forbidden` (if not the listing owner), `409 Conflict` (if there is an active trade linked to the listing).

---

### Trade Routes (`/api/trades`)

#### `GET /api/trades/my`
* **Description:** Lists the user's active (unresolved) trades.
* **Authorization:** Auth JWT Cookie
* **Success Response (200 OK):** `{ "trades": [ ... ] }`

#### `GET /api/trades/history`
* **Description:** Lists the user's completed trade history (RESOLVED, CANCELED, BURNED).
* **Authorization:** Auth JWT Cookie
* **Query Parameters:** `page`, `limit`
* **Success Response (200 OK):** `{ "trades": [ ... ], "total": 5, "page": 1, "limit": 10 }`

#### `GET /api/trades/by-escrow/:onchainId`
* **Description:** Returns the Trade document based on the on-chain escrow ID. Used on the frontend to access Trade._id instead of Listing._id. Only the parties involved in the trade can access it.
* **Authorization:** Auth JWT Cookie
* **Success Response (200 OK):**
```json
{ "trade": { "_id": "...", "onchain_escrow_id": 42, "maker_address": "0x...", "taker_address": "0x...", "status": "LOCKED" } }
```

#### `POST /api/trades/propose-cancel`
* **Description:** Saves an EIP-712 signature. When both parties sign, it returns `bothSigned: true` and becomes ready for on-chain submission.
* **Authorization:** Auth JWT Cookie
* **Request Body:**
```json
{
  "tradeId": "mongodb_objectid",
  "signature": "0x...",
  "deadline": 1735000000
}
```
* **Success Response (200 OK):**
```json
{ "success": true, "bothSigned": false, "message": "Proposal saved. Waiting for the counterparty's signature." }
```

#### `POST /api/trades/:id/chargeback-ack`
* **Description:** Records a legal acknowledgment that the Maker understands the "Chargeback" risk before releasing funds. IP hash (SHA-256) is stored, raw IP is never stored (GDPR compliant).
* **Authorization:** Auth JWT Cookie (Only Maker can call)
* **State Condition:** Trade must be `PAID` or `CHALLENGED`
* **Success Response (201 Created):**
```json
{ "success": true, "acknowledged_at": "2026-03-19T10:00:00.000Z" }
```

---

### PII Routes (`/api/pii`)

These routes are the highest security endpoints. Rate limit: 3 requests / 10 minutes (per IP + wallet).

#### `POST /api/pii/request-token/:tradeId`
* **Description:** **Step 1:** Requests a short-lived (15 min), trade-scoped PII token to access IBAN data.
* **Authorization:** Auth JWT Cookie (Only the Taker of the trade can call)
* **State Condition:** Trade must be `LOCKED`, `PAID`, or `CHALLENGED`
* **Success Response (200 OK):**
```json
{ "piiToken": "ey..." }
```

#### `GET /api/pii/:tradeId`
* **Description:** **Step 2:** Returns the seller's decrypted bank information using the short-lived PII token. The response is not logged or cached.
* **Authorization:** `Authorization: Bearer <piiToken>` header (not a cookie — trade-scoped and short-lived)
* **Success Response (200 OK):**
```json
{
  "bankOwner": "John Doe",
  "iban": "TR330006100519786457841326",
  "telegram": "john_tr",
  "notice": "This information is end-to-end encrypted. It is not stored on-chain or in logs."
}
```

---

### Other Routes

#### `GET /api/stats`
* **Description:** Returns global statistics of the protocol. Cached in Redis for 1 hour.
* **Authorization:** Public
* **Success Response (200 OK):**
```json
{
  "stats": {
    "total_volume_usdt": 123456.78,
    "completed_trades": 892,
    "active_listings": 34,
    "burned_bonds_usdt": 450.20,
    "avg_trade_hours": 2.4,
    "changes_30d": { "total_volume_usdt_pct": 12.5, "completed_trades_pct": 8.3 }
  }
}
```

#### `POST /api/feedback`
* **Description:** Submits user feedback. Max 3 requests per hour.
* **Authorization:** Auth JWT Cookie
* **Request Body:**
```json
{
  "rating": 5,
  "comment": "Great platform!",
  "category": "suggestion"
}
```
> `category` is required: `"bug"`, `"suggestion"`, `"ui/ux"`, `"other"`
* **Success Response (201 Created):** `{ "success": true }`

#### `GET /health`
* **Description:** Returns the health status of the backend and event listener. Used by the Fly.io health check.
* **Authorization:** Public
* **Success Response (200 OK):**
```json
{ "status": "ok", "worker": "active", "timestamp": "2026-03-19T10:00:00.000Z" }
```
