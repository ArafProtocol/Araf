# Araf Protocol — Deployment Guide

> **Version:** 2.0 | **Last Updated:** March 2026
>
> This guide covers three environments: Local Development · Public Testnet (Base Sepolia) · Mainnet (Base)

---

## Table of Contents

1. [Local Development](#1-local-development)
2. [Common Local Issues (Troubleshooting)](#2-common-local-issues-troubleshooting)
3. [Public Testnet — Base Sepolia](#3-public-testnet--base-sepolia)
4. [Mainnet — Base](#4-mainnet--base)
5. [Environment Differences Summary](#5-environment-differences-summary)

---

## 1. Local Development

### Prerequisites
- Node.js `v18+`
- Docker Desktop (easiest way for MongoDB and Redis)
- MetaMask — Hardhat network will be added

### Step 1 — Database & Cache (Setup via Docker)
MongoDB and Redis must be running for the backend to function. If Docker is installed, you can start them in the background by running these commands in your terminal:

```bash
# Start MongoDB
docker run -d --name araf-mongo -p 27017:27017 mongo:latest

# Start Redis
docker run -d --name araf-redis -p 6379:6379 redis:latest
```
*(To stop: `docker stop araf-mongo araf-redis`)*

### Step 2 — Install Dependencies

```bash
# In the project root directory
cd contracts && npm install && cd ..
cd backend  && npm install && cd ..
cd frontend && npm install && cd ..
```

### Step 3 — Terminal 1: Hardhat Node

```bash
cd contracts
npx hardhat node
```

The output will list 20 test wallets and their private keys. `Account #0` will be used as the deployer, and `Account #1` as the treasury.

### Step 4 — Terminal 2: Deploy Contracts

```bash
# Create contracts/.env file
cat > contracts/.env << 'EOF'
# Enter Account #1 address here
TREASURY_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# Account #0 private key
DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
EOF

npx hardhat run scripts/deploy.js --network hardhat
```

Note the following values from the output:
```text
VITE_ESCROW_ADDRESS="0x..."
VITE_USDT_ADDRESS="0x..."
VITE_USDC_ADDRESS="0x..."
```

### Step 5 — Terminal 2: Backend Configuration

```bash
# Create backend/.env file
cat > backend/.env << 'EOF'
PORT=4000
NODE_ENV=development

MONGODB_URI=mongodb://127.0.0.1:27017/araf_dev
REDIS_URL=redis://127.0.0.1:6379

# Generate a minimum 64-character string:
# node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_SECRET=generate_your_own_64_character_string_here
JWT_EXPIRES_IN=15m
PII_TOKEN_EXPIRES_IN=15m

KMS_PROVIDER=env
# node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
MASTER_ENCRYPTION_KEY=generate_your_own_32_byte_string_here

BASE_RPC_URL=[http://127.0.0.1:8545](http://127.0.0.1:8545)
ARAF_ESCROW_ADDRESS=<address_from_deploy_output>
CHAIN_ID=31337

TREASURY_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8

# Use Account #2 private key for Relayer
RELAYER_PRIVATE_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a

SIWE_DOMAIN=localhost
ALLOWED_ORIGINS=http://localhost:5173
EOF

cd backend && npm run dev
```

### Step 6 — Terminal 3: Frontend Configuration

```bash
# Create frontend/.env.development file
cat > frontend/.env.development << 'EOF'
VITE_API_URL=http://localhost:4000
VITE_ESCROW_ADDRESS=<address_from_deploy_output>
VITE_USDT_ADDRESS=<usdt_address_from_deploy_output>
VITE_USDC_ADDRESS=<usdc_address_from_deploy_output>
EOF

cd frontend && npm run dev
```

### Step 7 — Add MetaMask Hardhat Network

| Field | Value |
|------|-------|
| Network Name | Hardhat Local |
| RPC URL | `http://127.0.0.1:8545` |
| Chain ID | `31337` |
| Currency | ETH |

Import the test private keys provided by Hardhat into your MetaMask.

### Step 8 — Run Tests

```bash
cd contracts

# Including K-04/K-05 fixes — all tests should pass
npx hardhat test

# Coverage report (optional)
npx hardhat coverage
```

### Local Test Checklist

- [ ] `npx hardhat node` — 20 accounts visible
- [ ] `npx hardhat test` — all tests ✅
- [ ] Backend `http://localhost:4000/health` → `{"status":"ok"}`
- [ ] Frontend `http://localhost:5173` — opens successfully
- [ ] MetaMask on Hardhat network — `chainId: 31337`
- [ ] Get Test USDT button — mock faucet works
- [ ] Full trade lifecycle: create → lock → pay → release

---

## 2. Common Local Issues (Troubleshooting)

The most common issues encountered when developing locally (or in Codespaces) and their solutions:

### ❌ Port Already in Use (EADDRINUSE)
If you get this error when starting the Backend (`4000`) or Frontend (`5173`), there is a "zombie" Node.js process left open in the background.

**Solution (Free up the port):**
```bash
# For Mac and Linux (Kills all node processes):
killall -9 node

# For Windows (PowerShell):
taskkill /F /IM node.exe
```
If you want to kill only a specific port (e.g., 4000):
```bash
# Mac/Linux:
lsof -i :4000
kill -9 <PID_NUMBER>
```

### ❌ MetaMask Nonce Error (Transaction Pending/Stuck)
When you restart the Hardhat node (Terminal 1), the blockchain is "reset". However, your MetaMask wallet remembers the transaction sequence (Nonce) from the old sessions. This locks up the wallet when you try to send a new transaction.

**Solution (Reset Account):**
1. Open the MetaMask extension.
2. Go to **Settings** from the three dots (or profile picture) in the top right.
3. Click the **Advanced** tab.
4. Click the **"Clear Activity Data"** button. (This does not delete your balance or accounts, it only resets the transaction history).

### ❌ Codespaces Resource Limits (Resource Pressure)
GitHub Codespaces (Free tier) can quickly hit RAM limits when running MongoDB, Redis, Hardhat, Backend, and Frontend simultaneously. If your Codespace crashes or the terminal freezes:

**Solution:**
1. Temporarily Stop Docker Containers: If you are only designing the Frontend, shut down the backend/database duo: `docker stop araf-mongo araf-redis`.
2. Clone Locally (Recommended): If you are going to run full integration tests, pull the project directly to your own computer using `git clone` and work without limitations (using Docker Desktop).

### 🔎 Centralized Error Monitoring
Thanks to our error-catching system, all system events (including UI crashes, contract cancellations, API rejections) are accumulated in a single file. Always keep this log open in a terminal tab while developing:

```bash
# In the root directory (or backend directory)
tail -f araf_full_stack.log.txt
```

---

## 3. Public Testnet — Base Sepolia

### Prerequisites
- Base Sepolia network configured in MetaMask
- Base Sepolia ETH (Faucet: `faucet.quicknode.com` or `sepoliafaucet.com`)
- Alchemy/Infura account (for RPC)
- MongoDB Atlas account (free M0)
- Upstash Redis account (free)
- Fly.io account (for backend)
- Vercel account (for frontend)
- BaseScan API key (`basescan.org/myapikey`)

### Step 1 — Deploy Contracts (Base Sepolia)

```bash
# Update contracts/.env
cat > contracts/.env << 'EOF'
DEPLOYER_PRIVATE_KEY=0x<testnet_deployer_private_key>
TREASURY_ADDRESS=0x<testnet_treasury_wallet>
BASE_SEPOLIA_RPC_URL=[https://base-sepolia.g.alchemy.com/v2/](https://base-sepolia.g.alchemy.com/v2/)<API_KEY>
BASESCAN_API_KEY=<basescan_api_key>
REPORT_GAS=true
EOF

cd contracts

# Compile
npx hardhat compile

# Deploy
npx hardhat run scripts/deploy.js --network base-sepolia
```

Take note from the output:
```text
✅ ArafEscrow deployed:       0x...
✅ MockUSDT deployed:         0x...
✅ MockUSDC deployed:         0x...
✅ Ownership transferred →    0x<treasury>
```

### Step 2 — Verify Contracts (BaseScan)

```bash
cd contracts

# Verify ArafEscrow
npx hardhat verify --network base-sepolia \
  <ARAF_ESCROW_ADDRESS> \
  <TREASURY_ADDRESS>

# Verify MockUSDT
npx hardhat verify --network base-sepolia \
  <USDT_ADDRESS> \
  "Mock USDT" "USDT" 6

# Verify MockUSDC
npx hardhat verify --network base-sepolia \
  <USDC_ADDRESS> \
  "Mock USDC" "USDC" 6
```

### Step 3 — Backend: Deploy to Fly.io

```bash
# Install Fly.io CLI (macOS/Linux)
curl -L [https://fly.io/install.sh](https://fly.io/install.sh) | sh

# Login
fly auth login

# Go to backend directory
cd backend

# Create app (first time)
fly apps create araf-protocol-backend

# Set secrets (all at once)
fly secrets set \
  NODE_ENV="production" \
  MONGODB_URI="mongodb+srv://<user>:<pass>@cluster.mongodb.net/araf_testnet" \
  REDIS_URL="rediss://:<token>@<host>.upstash.io:6379" \
  JWT_SECRET="<64_character_hex>" \
  JWT_EXPIRES_IN="15m" \
  PII_TOKEN_EXPIRES_IN="15m" \
  KMS_PROVIDER="env" \
  MASTER_ENCRYPTION_KEY="<32_byte_hex>" \
  BASE_RPC_URL="[https://base-sepolia.g.alchemy.com/v2/](https://base-sepolia.g.alchemy.com/v2/)<API_KEY>" \
  BASE_WS_RPC_URL="wss://[base-sepolia.g.alchemy.com/v2/](https://base-sepolia.g.alchemy.com/v2/)<API_KEY>" \
  ARAF_ESCROW_ADDRESS="<DEPLOY_ADDRESS>" \
  CHAIN_ID="84532" \
  TREASURY_ADDRESS="<TREASURY_WALLET>" \
  RELAYER_PRIVATE_KEY="0x<relayer_private_key>" \
  SIWE_DOMAIN="araf-protocol-backend.fly.dev" \
  ALLOWED_ORIGINS="[https://araf-protocol.vercel.app](https://araf-protocol.vercel.app)"

# Deploy
fly deploy

# Watch logs
fly logs --app araf-protocol-backend
```

> **Note:** The `auto_stop_machines = false` setting in the `fly.toml` file is mandatory for the event listener to run continuously. Do not change it.

### Step 4 — Frontend: Deploy to Vercel

```bash
# Install Vercel CLI
npm install -g vercel

# Go to frontend directory
cd frontend

# Update the proxy URL in vercel.json
# "destination" → "[https://araf-protocol-backend.fly.dev/api/$1](https://araf-protocol-backend.fly.dev/api/$1)"

# Create Production env file
cat > .env.production << 'EOF'
VITE_API_URL=[https://araf-protocol-backend.fly.dev](https://araf-protocol-backend.fly.dev)
VITE_ESCROW_ADDRESS=<DEPLOY_ADDRESS>
VITE_USDT_ADDRESS=<USDT_ADDRESS>
VITE_USDC_ADDRESS=<USDC_ADDRESS>
EOF

# Deploy
vercel --prod

# or for automatic deploy with GitHub integration:
# vercel link → connect GitHub repo → auto deploy on every main push
```

Environment Variables must also be set in Vercel (Dashboard → Settings → Environment Variables).

### Step 5 — Update SIWE Domain

Once the backend deploy URL is established:

```bash
# Set SIWE_DOMAIN in Backend to match frontend domain
fly secrets set SIWE_DOMAIN="araf-protocol.vercel.app"
```

### Step 6 — Remove Hardhat Chain from main.jsx

```jsx
// frontend/src/main.jsx — hardhat chain is not needed for testnet
import { base, baseSepolia } from 'wagmi/chains'
// remove hardhat import

const config = createConfig({
  chains: [base, baseSepolia], // hardhat removed
  transports: {
    [base.id]:       http(),
    [baseSepolia.id]: http(),
  },
})
```

### Testnet Checklist

- [ ] `https://sepolia.basescan.org/address/<ESCROW_ADDRESS>` — contract verified ✅
- [ ] `https://araf-protocol-backend.fly.dev/health` → `{"status":"ok","worker":"active"}`
- [ ] `https://araf-protocol.vercel.app` — site opens
- [ ] MetaMask connected to Base Sepolia
- [ ] Test USDT/USDC faucet is working
- [ ] SIWE login successful
- [ ] Full trade lifecycle: create → lock → pay → release
- [ ] Dispute → bleeding → cancel
- [ ] Event listener logs are clean (`fly logs`)

---

## 4. Mainnet — Base

> ⚠️ **Mandatory before Mainnet:** A professional smart contract security audit must be completed.

### Testnet vs Mainnet Differences

| Field | Testnet | Mainnet |
|------|---------|---------|
| MockERC20 | Deployed | **Not Deployed** (`NODE_ENV=production`) |
| KMS | `env` (temporary) | AWS KMS or HashiCorp Vault |
| Treasury | Test wallet | **Gnosis Safe multisig** (min 3/5) |
| RPC | Alchemy Sepolia | Alchemy/Infura Base Mainnet |
| Chain ID | 84532 | 8453 |
| Relayer | Manual wallet | Gelato Automation (recommended) |
| Audit | Optional | **Mandatory** |

### Step 1 — Gnosis Safe Preparation

1. `safe.global` → Base Mainnet → New Safe
2. Configure a minimum of 3/5 signers
3. Use the Safe address as the `TREASURY_ADDRESS`
4. **Do not use a single EOA treasury** — if the private key leaks, all protocol funds are at risk.

### Step 2 — AWS KMS Setup (Production Encryption)

```bash
# Create KMS key via AWS CLI
aws kms create-key \
  --description "Araf Protocol PII Master Key" \
  --region eu-west-1

# Generate data key (plaintext + encrypted)
aws kms generate-data-key \
  --key-id <KMS_KEY_ARN> \
  --key-spec AES_256 \
  --region eu-west-1

# Take the encrypted data key from the output (CiphertextBlob → base64)
# Save it to the AWS_ENCRYPTED_DATA_KEY variable
```

### Step 3 — Deploy Contracts (Base Mainnet)

```bash
# Update contracts/.env
cat > contracts/.env << 'EOF'
DEPLOYER_PRIVATE_KEY=0x<mainnet_deployer_private_key>
TREASURY_ADDRESS=0x<gnosis_safe_address>
BASE_RPC_URL=[https://base-mainnet.g.alchemy.com/v2/](https://base-mainnet.g.alchemy.com/v2/)<API_KEY>
BASESCAN_API_KEY=<basescan_api_key>
EOF

# Set NODE_ENV to production so MockERC20 is NOT deployed
NODE_ENV=production npx hardhat run scripts/deploy.js --network base

# Verify
npx hardhat verify --network base <ESCROW_ADDRESS> <GNOSIS_SAFE_ADDRESS>
```

### Step 4 — Backend: Production Secrets

```bash
# Fly.io production secrets
fly secrets set \
  NODE_ENV="production" \
  KMS_PROVIDER="aws" \
  AWS_KMS_KEY_ARN="arn:aws:kms:eu-west-1:...:key/..." \
  AWS_ENCRYPTED_DATA_KEY="<base64_CiphertextBlob>" \
  AWS_REGION="eu-west-1" \
  BASE_RPC_URL="[https://base-mainnet.g.alchemy.com/v2/](https://base-mainnet.g.alchemy.com/v2/)<API_KEY>" \
  BASE_WS_RPC_URL="wss://[base-mainnet.g.alchemy.com/v2/](https://base-mainnet.g.alchemy.com/v2/)<API_KEY>" \
  CHAIN_ID="8453" \
  ARAF_ESCROW_ADDRESS="<MAINNET_ESCROW>" \
  TREASURY_ADDRESS="<GNOSIS_SAFE>" \
  SIWE_DOMAIN="app.araf.xyz" \
  ALLOWED_ORIGINS="[https://app.araf.xyz](https://app.araf.xyz)"
  # RELAYER_PRIVATE_KEY → Use Gelato Automation on Mainnet

fly deploy
```

### Step 5 — Frontend Production Configuration

```bash
# main.jsx — mainnet only
import { base } from 'wagmi/chains'

# .env.production
VITE_API_URL=[https://api.araf.xyz](https://api.araf.xyz)
VITE_ESCROW_ADDRESS=<MAINNET_ESCROW>
# VITE_USDT_ADDRESS and VITE_USDC_ADDRESS → real Base USDT/USDC addresses
# Base USDT: 0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2
# Base USDC: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

vercel --prod
```

### Mainnet Checklist

- [ ] Security audit report is ready and findings are resolved
- [ ] Gnosis Safe multisig is configured (min 3/5)
- [ ] AWS KMS is active and encrypted data key is tested
- [ ] `NODE_ENV=production` — MockERC20 was not deployed ✅
- [ ] Contract verified on BaseScan
- [ ] Ownership transferred to Gnosis Safe ✅
- [ ] `pause()` / `unpause()` is operational from Gnosis Safe
- [ ] Event listener is stable on WSS RPC
- [ ] DLQ monitor alert webhook is active (Slack/PagerDuty)
- [ ] `GET /health` → worker: active
- [ ] Real USDT/USDC addresses are correct on the frontend
- [ ] SIWE domain matches the production domain
- [ ] Rate limit tests passed

---

## 5. Environment Differences Summary

| Parameter | Local | Testnet | Mainnet |
|-----------|-------|---------|---------|
| `NODE_ENV` | `development` | `production` | `production` |
| `KMS_PROVIDER` | `env` | `env` *(temp)* | `aws` / `vault` |
| `MockERC20` | ✅ Deployed | ✅ Deployed | ❌ Not Deployed |
| `CHAIN_ID` | `31337` | `84532` | `8453` |
| `SIWE_DOMAIN` | `localhost` | `*.fly.dev` / `*.vercel.app` | real domain |
| Treasury | Test wallet | Test wallet | Gnosis Safe |
| Relayer | Hardhat wallet | Separate test wallet | Gelato Automation |
| RPC | `http://localhost:8545` | Alchemy Sepolia | Alchemy/Infura Base |
| WSS RPC | Not Required | Recommended | **Mandatory** |
| Audit | No | No | **Mandatory** |

### Quick Command Reference

```bash
# Tests
cd contracts && npx hardhat test

# Local deploy
npx hardhat run scripts/deploy.js --network hardhat

# Testnet deploy
npx hardhat run scripts/deploy.js --network base-sepolia

# Mainnet deploy
NODE_ENV=production npx hardhat run scripts/deploy.js --network base

# Verify (testnet)
npx hardhat verify --network base-sepolia <ADDRESS> <TREASURY>

# Fly.io backend logs
fly logs --app araf-protocol-backend

# Fly.io update secret
fly secrets set KEY=VALUE

# Vercel production deploy
cd frontend && vercel --prod
```

### Useful Links

| Service | Link |
|--------|------|
| Base Sepolia Faucet | `faucet.quicknode.com` |
| BaseScan Testnet | `sepolia.basescan.org` |
| BaseScan Mainnet | `basescan.org` |
| Alchemy | `dashboard.alchemy.com` |
| Fly.io Dashboard | `fly.io/dashboard` |
| Vercel Dashboard | `vercel.com/dashboard` |
| Gnosis Safe | `app.safe.global` |
| AWS KMS | `console.aws.amazon.com/kms` |

---

*Araf Protocol — "Trust the Time, Not the Oracle."*
