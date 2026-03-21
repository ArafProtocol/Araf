```
araf-protocol/
│
├── 📄 .gitignore
├── 📄 README.md
│
├── 📁 contracts/                          # Solidity Smart Contract Layer
│   ├── 📄 hardhat.config.js               # Hardhat configuration (Base L2, Solidity 0.8.24)
│   ├── 📄 package.json
│   ├── 📄 .env.example                    # Contract environment variables template
│   │
│   ├── 📁 src/
│   │   ├── 📄 ArafEscrow.sol              # Main contract v2.1 (Bleeding Escrow + Anti-Sybil + EIP-712 + Tier Limits)
│   │   └── 📄 MockERC20.sol               # Test token — faucet mint() + admin mint(address,uint256)
│   │
│   ├── 📁 scripts/
│   │   └── 📄 deploy.js                   # Deploy script (Auto-copies ABI to frontend, ownership transfer)
│   │
│   └── 📁 test/
│       └── 📄 ArafEscrow.test.js          # Full test suite v2.1 (Happy path, Tier Limits K-05, Anti-Sybil, Bleeding, Cancel)
│
├── 📁 backend/                            # Node.js + Express Web2.5 API
│   ├── 📄 package.json
│   ├── 📄 .env.example                    # Environment variables template
│   ├── 📄 env.example                     # Alternative env template (duplicate)
│   ├── 📄 Dockerfile                      # Alpine Node.js production image
│   ├── 📄 fly.toml                        # Fly.io deploy configuration
│   ├── 📄 .dockerignore
│   │
│   └── 📁 scripts/
│       ├── 📄 app.js                      # Main application (Bootstrap + Routes + DLQ + Graceful Shutdown)
│       │
│       ├── 📁 config/
│       │   ├── 📄 db.js                   # MongoDB connection manager (connection pool)
│       │   └── 📄 redis.js                # Redis connection manager (rate limiting + nonces + DLQ)
│       │
│       ├── 📁 models/
│       │   ├── 📄 User.js                 # User model (encrypted PII + reputation cache + ban state)
│       │   ├── 📄 Trade.js                # Listing + Trade schemas (evidence + receipt TTL + chargeback ack)
│       │   ├── 📄 Feedback.js             # Feedback schema (category + GDPR TTL)
│       │   └── 📄 HistoricalStat.js       # Daily protocol statistics snapshot (for stats endpoint)
│       │
│       ├── 📁 routes/
│       │   ├── 📄 auth.js                 # SIWE + JWT + httpOnly cookie + profile update
│       │   ├── 📄 listings.js             # Marketplace CRUD (on-chain tier validation + bond config)
│       │   ├── 📄 trades.js               # Trade room + EIP-712 cancel + chargeback ack + by-escrow
│       │   ├── 📄 pii.js                  # 🔐 2-step IBAN fetch + /my + /taker-name triangulation
│       │   ├── 📄 receipts.js             # 🔐 Encrypted receipt upload (AES-256-GCM + SHA-256 hash)
│       │   ├── 📄 feedback.js             # User feedback (category required)
│       │   └── 📄 stats.js                # Protocol statistics (Redis 1s cache + 30-day comparison)
│       │   └── 📄 logs.js                 # League management 
│       │
│       ├── 📁 middleware/
│       │   ├── 📄 auth.js                 # requireAuth (httpOnly cookie) + requirePIIToken (Bearer)
│       │   ├── 📄 rateLimiter.js          # Redis sliding window (6 levels: PII/Auth/Listings/Trades/Feedback)
│       │   └── 📄 errorHandler.js         # Global error handler (Mongoose + JWT + generic)
│       │
│       ├── 📁 services/
│       │   ├── 📄 siwe.js                 # SIWE flow + JWT + refresh token rotation (Redis SCAN)
│       │   ├── 📄 encryption.js           # AES-256-GCM envelope encryption (HKDF + KMS-ready: env/aws/vault)
│       │   ├── 📄 eventListener.js        # Chain listener (on-chain → MongoDB + FIFO DLQ + checkpoint)
│       │   ├── 📄 dlqProcessor.js         # Dead Letter Queue monitor (archive + alert cooldown)
│       │   └── 📄 protocolConfig.js       # Loads on-chain bond parameters on startup (Redis cache)
│       │
│       ├── 📁 jobs/
│       │   ├── 📄 reputationDecay.js      # Triggers 180-day clean slate rule on-chain (Relayer)
│       │   └── 📄 statsSnapshot.js        # Daily statistics snapshot (aggregation pipeline)
│       │
│       └── 📁 utils/
│           └── 📄 logger.js               # Winston logger (JSON format, log level based on environment)
│
├── 📁 frontend/                           # React + Vite + Tailwind
│   ├── 📄 index.html
│   ├── 📄 package.json
│   ├── 📄 vite.config.js
│   ├── 📄 tailwind.config.js
│   ├── 📄 postcss.config.js
│   ├── 📄 vercel.json                     # Vercel deploy (API proxy + security headers)
│   ├── 📄 .env.example                    # Frontend environment variables template
│   │
│   └── 📁 src/
│       ├── 📄 main.jsx                    # Wagmi + React Query Provider (ErrorBoundary wrapper)
│       ├── 📄 App.jsx                     # 🎨 Main UI (Marketplace + Trade Room + Profile + SIWE + Cookie auth)
│       ├── 📄 index.css                   # Tailwind + custom animations (bounce-in, pulse-slow)
│       │
│       ├── 📁 components/
│       │   ├── 📄 ErrorBoundary.jsx       # Global render error boundary
│       │   └── 📄 PIIDisplay.jsx          # 🔐 Encrypted IBAN display (2-step + copy + Telegram)
│       │
│       ├── 📁 hooks/
│       │   ├── 📄 usePII.js               # 2-step PII fetch (auto-cleanup, cookie-only auth)
│       │   ├── 📄 useArafContract.js      # All contract interactions (write/read/EIP-712, chain guard)
│       │   └── 📄 useCountdown.js         # Countdown hook to target date (second-based)
│       │
│       └── 📁 abi/
│           └── 📄 ArafEscrow.json         # Auto-generated by deploy script
│
└── 📁 docs/                               # Architectural & Operational Documentation
│   ├── 📁 tr/                             # Turkish Documentation
│   │   ├── 📄 ARCHITECTURE.md             # Protocol architecture (Technical reference)
│   │   ├── 📄 API_DOCUMENTATION.md        # Backend API endpoint reference
│   │   ├── 📄 LOCAL_DEVELOPMENT.md        # Local development setup guide
│   │   ├── 📄 GAME_THEORY.md              # Game theory and Bleeding Escrow flow
│   │   └── 📄 UX_FLOW.md                  # User experience and flowcharts
│   │
│   ├── 📁 en/                             # English Documentation
│   │   ├── 📄 ARCHITECTURE.md             # Protocol architecture (Technical reference)
│   │   ├── 📄 API_DOCUMENTATION.md        # Backend API endpoint reference
│   │   ├── 📄 LOCAL_DEVELOPMENT.md        # Local development setup guide
│   │   ├── 📄 GAME_THEORY.md              # Game theory & Bleeding Escrow logic
│   │   └── 📄 UX_FLOW.md                  # UX flow and diagrams
```
## File Counts

| Layer | File Count |
|--------|-------------|
| Contract (`contracts/`) | 5 |
| Backend (`backend/scripts/`) | 18 |
| Frontend (`frontend/src/`) | 9 |
| Documentation (`docs/`) | 14 |
| **Total** | **~46** |

---

## Critical Files (Think Before Touching)

| File | Why It's Critical |
|-------|-------------|
| `contracts/src/ArafEscrow.sol` | Main contract — immutable after deployment |
| `backend/scripts/services/encryption.js` | Master key management — wrong changes lead to PII data loss |
| `backend/scripts/services/eventListener.js` | On-chain synchronization — state inconsistency if FIFO order breaks |
| `frontend/src/hooks/useArafContract.js` | All contract interactions — ABI mismatch breaks all txs |
| `backend/scripts/services/siwe.js` | JWT secrecy — entropy check runs on startup |
