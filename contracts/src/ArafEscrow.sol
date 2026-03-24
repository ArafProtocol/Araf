/*
 * Copyright 2026 Araf Protocol
 *
 * Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

pragma solidity ^0.8.24;

/**
 * @title  ArafEscrow
 * @notice Oracle kullanmayan, P2P itibari para ↔ kripto takas kontratı.
 *         Zamanla eriyen (Bleeding Escrow) anlaşmazlık çözüm mekanizması içerir.
 * @notice Oracle-free P2P fiat ↔ crypto escrow with Bleeding Escrow (time-decay) dispute resolution.
 * @dev    Security: ReentrancyGuard + CEI pattern + EIP-712 cancel. Network: Base (L2)
 * @author Araf Protocol — v2.1
 */

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// ═══════════════════════════════════════════════════
//  ÖZEL HATALAR — require() string'lerine göre daha az gaz harcar
//  CUSTOM ERRORS — cheaper gas than require() strings
// ═══════════════════════════════════════════════════
error NotTradeParty();
error InvalidState();
error TakerBanActive();
error OnlyMaker();
error OnlyTaker();
error AlreadyRegistered();
error TokenNotSupported();
error ZeroAmount();
error InvalidTier();
error TierNotAllowed();
error AmountExceedsTierLimit(); // C-04: Tier limit aşımı / tier cap exceeded
error SelfTradeForbidden();
error WalletTooYoung();
error InsufficientNativeBalance();
error TierCooldownActive();
error EmptyIpfsHash();
error CannotReleaseInState();
error PingCooldownNotElapsed(uint256 requiredTime);
error AlreadyPinged();
error MustPingFirst();
error ResponseWindowActive();
error SignatureExpired();
error InvalidSignature();
error BurnPeriodNotReached();
error NoPriorBanHistory();
error CleanPeriodNotElapsed();
error NoBansToReset();
error DeadlineTooFar();
error ConflictingPingPath();

contract ArafEscrow is ReentrancyGuard, EIP712, Ownable, Pausable {
    using SafeERC20 for IERC20;

    // ═══════════════════════════════════════════════════
    //  VERİ YAPILARI — Enum'lar ve Struct'lar
    //  DATA STRUCTURES — Enums & Structs
    // ═══════════════════════════════════════════════════

    enum TradeState {
        OPEN,       // Maker fon kilitledi, ilan açık / Maker locked funds, listing live
        LOCKED,     // Taker eşleşti, fonlar güvende / Taker matched, funds secured
        PAID,       // Taker ödeme bildirdi, 48s bekle / Taker reported payment, 48h grace
        CHALLENGED, // Maker itiraz etti, Bleeding aktif / Maker disputed, Bleeding active
        RESOLVED,   // Başarıyla tamamlandı / Successfully closed
        CANCELED,   // Karşılıklı 2/2 iptal / Mutual cancel
        BURNED      // 10 gün timeout — tümü hazineye / 10-day timeout, all to treasury
    }

    struct Trade {
        uint256 id;
        address maker;
        address taker;
        address tokenAddress;        // USDT / USDC on Base
        uint256 cryptoAmount;        // Kilitli kripto miktarı / locked crypto
        uint256 makerBond;           // Maker teminatı / maker's bond
        uint256 takerBond;           // Taker teminatı, Tier 0'da sıfır / taker's bond (0 for Tier 0)
        uint8   tier;                // 0–4
        TradeState state;
        uint256 lockedAt;
        uint256 paidAt;
        uint256 challengedAt;
        string  ipfsReceiptHash;     // Taker ödeme dekontu / taker's payment proof
        bool    cancelProposedByMaker;
        bool    cancelProposedByTaker;
        // [TR] Taker'ın Maker'a "hayatta mısın?" sinyali — autoRelease ön koşulu
        // [EN] Taker's liveness signal to Maker — required before autoRelease
        uint256 pingedAt;
        bool    pingedByTaker;
        // [TR] Maker'ın itiraz öncesi Taker'a uyarısı — challengeTrade ön koşulu
        // [EN] Maker's pre-challenge warning to Taker — required before challengeTrade
        uint256 challengePingedAt;
        bool    challengePingedByMaker;
    }

    struct Reputation {
        uint256 successfulTrades;
        uint256 failedDisputes;
        uint256 bannedUntil;      // 0 = yasak yok / 0 = not banned
        uint256 consecutiveBans;  // Ard arda ban sayısı, süre ve tier cezası için / consecutive ban count
    }

    // ═══════════════════════════════════════════════════
    //  SABİTLER — Protokol Parametreleri v2.1
    //  CONSTANTS — Protocol Parameters v2.1
    // ═══════════════════════════════════════════════════

    // [TR] 5 Katmanlı Teminat Sistemi (BPS: 100 = %1)
    // [EN] 5-Tier Bond System (BPS: 100 = 1%)
    //
    // Tier 0 | 150 USDT maks     | Maker %0  | Taker %0  | Yeni kullanıcı teşviki
    // Tier 1 | 1.500 USDT maks   | Maker %8  | Taker %10 | 1:1.25 asimetri
    // Tier 2 | 7.500 USDT maks   | Maker %6  | Taker %8  | 1:1.33 asimetri
    // Tier 3 | 30.000 USDT maks  | Maker %5  | Taker %5  | 1:1 eşit güven
    // Tier 4 | Limitsiz          | Maker %2  | Taker %2  | Premium, düşük yük

    uint256 public constant MAKER_BOND_TIER0_BPS =    0; //  0%
    uint256 public constant MAKER_BOND_TIER1_BPS =  800; //  8%
    uint256 public constant MAKER_BOND_TIER2_BPS =  600; //  6%
    uint256 public constant MAKER_BOND_TIER3_BPS =  500; //  5%
    uint256 public constant MAKER_BOND_TIER4_BPS =  200; //  2%

    uint256 public constant TAKER_BOND_TIER0_BPS =    0; //  0%
    uint256 public constant TAKER_BOND_TIER1_BPS = 1000; // 10%
    uint256 public constant TAKER_BOND_TIER2_BPS =  800; //  8%
    uint256 public constant TAKER_BOND_TIER3_BPS =  500; //  5%
    uint256 public constant TAKER_BOND_TIER4_BPS =  200; //  2%

    // [TR] Tier başına kripto maks limit (6 decimal — USDT/USDC)
    // [EN] Max crypto per tier (6 decimals — USDT/USDC). Tier 4 = unlimited (0)
    uint256 public constant TIER_MAX_AMOUNT_TIER0 =    150 * 10**6; // 150 USDT
    uint256 public constant TIER_MAX_AMOUNT_TIER1 =   1500 * 10**6; // 1.500 USDT
    uint256 public constant TIER_MAX_AMOUNT_TIER2 =   7500 * 10**6; // 7.500 USDT
    uint256 public constant TIER_MAX_AMOUNT_TIER3 =  30000 * 10**6; // 30.000 USDT
    // Tier 4 = limitsiz / unlimited → _getTierMaxAmount returns 0

    // [TR] İtibar çarpanları — bond BPS'i artırır veya azaltır
    // [EN] Reputation modifiers — adjusts bond BPS up or down
    uint256 public constant GOOD_REP_DISCOUNT_BPS = 100; // -1% (temiz geçmiş / clean history)
    uint256 public constant BAD_REP_PENALTY_BPS   = 300; // +3% (ceza / penalty)

    // [TR] Protokol kesintisi — her iki taraftan %0.1, toplam %0.2/işlem
    // [EN] Protocol fee — 0.1% each side, 0.2% total per trade
    uint256 public constant TAKER_FEE_BPS = 10;
    uint256 public constant MAKER_FEE_BPS = 10;

    // [TR] autoRelease tetiklendiğinde her iki tarafın teminatından alınan ihmal cezası
    // [EN] Negligence penalty deducted from both bonds when autoRelease is triggered
    uint256 public constant AUTO_RELEASE_PENALTY_BPS = 200; // 2%

    // [TR] Zamanlayıcılar
    // [EN] Timers
    uint256 public constant GRACE_PERIOD         =  48 hours; // Challenge sonrası cezasız pencere / post-challenge safe window
    uint256 public constant USDT_DECAY_START     =  96 hours; // Grace bittikten sonra crypto erimeye başlar / crypto decay starts after grace
    uint256 public constant MAX_BLEEDING         = 240 hours; // 10 gün → BURN / 10 days → BURN
    uint256 public constant WALLET_AGE_MIN       =   7 days;  // Anti-Sybil cüzdan yaşı / anti-Sybil wallet age
    uint256 public constant TIER0_TRADE_COOLDOWN =   4 hours; // Tier 0/1 soğuma süresi / Tier 0/1 cooldown
    uint256 public constant TIER1_TRADE_COOLDOWN =   4 hours;
    uint256 public constant MAX_CANCEL_DEADLINE  =   7 days;  // EIP-712 imza geçerlilik üst sınırı / EIP-712 sig max validity
    uint256 public constant MIN_ACTIVE_PERIOD    =  15 days;  // Sybil caydırıcı — Tier 1+ için min aktif süre / min active period for Tier 1+

    // [TR] Saatlik erime oranları (BPS/saat). Formül: decayed = amount * rate * seconds / (10000 * 3600)
    // [EN] Hourly decay rates (BPS/h). Formula: decayed = amount * rate * seconds / (10000 * 3600)
    // Efektif bleeding penceresi: 240h - 48h = 192h
    uint256 public constant TAKER_BOND_DECAY_BPS_H = 42; // 192h'de ~%80.6 erir / ~80.6% in 192h
    uint256 public constant MAKER_BOND_DECAY_BPS_H = 26; // 192h'de ~%50.1 erir / ~50.1% in 192h
    uint256 public constant CRYPTO_DECAY_BPS_H     = 34; // x2 uygular, USDT_DECAY_START'tan başlar / x2, starts after USDT_DECAY_START

    // [TR] Anti-Sybil — Base'de yaklaşık $2 değerinde minimum native bakiye
    // [EN] Anti-Sybil — minimum native balance, ~$2 on Base
    uint256 public constant DUST_LIMIT = 0.001 ether;

    uint256 private constant BPS_DENOMINATOR  = 10_000;
    uint256 private constant SECONDS_PER_HOUR = 3_600;

    // ═══════════════════════════════════════════════════
    //  EIP-712 TYPEHASH
    // ═══════════════════════════════════════════════════

    bytes32 private constant CANCEL_TYPEHASH = keccak256(
        "CancelProposal(uint256 tradeId,address proposer,uint256 nonce,uint256 deadline)"
    );

    // ═══════════════════════════════════════════════════
    //  DURUM DEĞİŞKENLERİ / STATE VARIABLES
    // ═══════════════════════════════════════════════════

    uint256 public tradeCounter;
    address public treasury;

    mapping(uint256 => Trade) public trades;
    mapping(address => Reputation) public reputation;

    // [TR] Anti-Sybil: cüzdan kayıt timestamp'i ve son işlem zamanı
    // [EN] Anti-Sybil: wallet registration timestamp and last trade time
    mapping(address => uint256) public walletRegisteredAt;
    mapping(address => uint256) public lastTradeAt;

    // [TR] Tier ceza sistemi: hasTierPenalty sentinel olmadan 0 değeri ayırt edilemez
    //      (Hiç ceza almamış ile Tier 0'a düşürülmüş aynı görünür)
    // [EN] Tier penalty system: hasTierPenalty sentinel distinguishes "no penalty" from "demoted to Tier 0"
    mapping(address => uint8) public maxAllowedTier;
    mapping(address => bool)  public hasTierPenalty;

    // [TR] İlk başarılı işlem zamanı — Sybil hızlı tier atlama caydırıcısı
    // [EN] First successful trade timestamp — deters Sybil fast-tier escalation
    mapping(address => uint256) public firstSuccessfulTradeAt;

    // [TR] Desteklenen ödeme tokenları (USDT, USDC on Base)
    // [EN] Supported payment tokens (USDT, USDC on Base)
    mapping(address => bool) public supportedTokens;

    // [TR] EIP-712 nonce — replay saldırılarını önler
    // [EN] EIP-712 nonce — replay attack protection
    mapping(address => uint256) public sigNonces;

    // ═══════════════════════════════════════════════════
    //  OLAYLAR / EVENTS
    // ═══════════════════════════════════════════════════

    event WalletRegistered(address indexed wallet, uint256 timestamp);
    event EscrowCreated(uint256 indexed tradeId, address indexed maker, address token, uint256 amount, uint8 tier);
    event EscrowLocked(uint256 indexed tradeId, address indexed taker, uint256 takerBond);
    event PaymentReported(uint256 indexed tradeId, string ipfsHash, uint256 timestamp);
    event EscrowReleased(uint256 indexed tradeId, address indexed maker, address indexed taker, uint256 takerFee, uint256 makerFee);
    event DisputeOpened(uint256 indexed tradeId, address indexed challenger, uint256 timestamp);
    event CancelProposed(uint256 indexed tradeId, address indexed proposer);
    event EscrowCanceled(uint256 indexed tradeId, uint256 makerRefund, uint256 takerRefund);
    event MakerPinged(uint256 indexed tradeId, address indexed pinger, uint256 timestamp);
    event BleedingDecayed(uint256 indexed tradeId, uint256 decayedAmount, uint256 timestamp);
    event EscrowBurned(uint256 indexed tradeId, uint256 burnedAmount);
    event ReputationUpdated(address indexed wallet, uint256 successful, uint256 failed, uint256 bannedUntil, uint8 effectiveTier);
    event TreasuryUpdated(address indexed newTreasury);
    event TokenSupportUpdated(address indexed token, bool supported);

    // ═══════════════════════════════════════════════════
    //  MODIFIER'LAR / MODIFIERS
    // ═══════════════════════════════════════════════════

    modifier inState(uint256 _tradeId, TradeState _expected) {
        if (trades[_tradeId].state != _expected) revert InvalidState();
        _;
    }

    modifier notBanned() {
        Reputation storage rep = reputation[msg.sender];
        if (rep.bannedUntil != 0 && block.timestamp <= rep.bannedUntil) revert TakerBanActive();
        _;
    }

    // ═══════════════════════════════════════════════════
    //  CONSTRUCTOR
    // ═══════════════════════════════════════════════════

    constructor(address _treasury)
        EIP712("ArafEscrow", "1")
        Ownable(msg.sender)
    {
        if (_treasury == address(0)) revert OwnableInvalidOwner(address(0));
        treasury = _treasury;
    }

    // ═══════════════════════════════════════════════════
    //  KAYIT — Anti-Sybil Cüzdan Yaşı Kapısı
    //  REGISTRATION — Anti-Sybil Wallet Age Gate
    // ═══════════════════════════════════════════════════

    /**
     * @notice Cüzdanı kaydeder ve 7 günlük yaşlanma sürecini başlatır.
     *         Taker olmadan önce çağrılmalıdır.
     * @notice Register wallet to start the 7-day aging countdown.
     *         Must be called before acting as Taker.
     */
    function registerWallet() external {
        if (walletRegisteredAt[msg.sender] != 0) revert AlreadyRegistered();
        walletRegisteredAt[msg.sender] = block.timestamp;
        emit WalletRegistered(msg.sender, block.timestamp);
    }

    // ═══════════════════════════════════════════════════
    //  MAKER AKIŞI — Escrow Oluşturma
    //  MAKER FLOW — Create Escrow
    // ═══════════════════════════════════════════════════

    /**
     * @notice Maker yeni bir P2P ilanı oluşturur. Kripto + teminat kilitlenir.
     *         Tier limit on-chain zorunlu tutulur (frontend bypass koruması).
     * @notice Maker creates a P2P listing. Locks crypto + bond.
     *         Tier amount cap enforced on-chain (protects against frontend bypass).
     * @param  _token         ERC20 token adresi (USDT/USDC) / token address
     * @param  _cryptoAmount  Satılacak miktar (6 decimal) / amount to sell
     * @param  _tier          0, 1, 2, 3 veya 4 / 0–4
     */
    function createEscrow(
        address _token,
        uint256 _cryptoAmount,
        uint8   _tier
    ) external nonReentrant whenNotPaused returns (uint256 tradeId) {
        // ── Checks ──
        if (!supportedTokens[_token]) revert TokenNotSupported();
        if (_cryptoAmount == 0) revert ZeroAmount();
        if (_tier > 4) revert InvalidTier();

        uint8 effectiveTier = _getEffectiveTier(msg.sender);
        if (_tier > effectiveTier) revert TierNotAllowed();

        // [TR] C-04: Tier başına kripto limiti on-chain zorunlu — frontend bypass'ı engeller
        // [EN] C-04: Tier crypto cap enforced on-chain — prevents direct contract bypass
        uint256 tierMax = _getTierMaxAmount(_tier);
        if (tierMax > 0 && _cryptoAmount > tierMax) revert AmountExceedsTierLimit();

        uint256 bondBps   = _getMakerBondBps(msg.sender, _tier);
        uint256 makerBond = (_cryptoAmount * bondBps) / BPS_DENOMINATOR;
        uint256 totalLock = _cryptoAmount + makerBond;

        // ── Effects ──
        tradeId = ++tradeCounter;
        trades[tradeId] = Trade({
            id:                     tradeId,
            maker:                  msg.sender,
            taker:                  address(0),
            tokenAddress:           _token,
            cryptoAmount:           _cryptoAmount,
            makerBond:              makerBond,
            takerBond:              0,
            tier:                   _tier,
            state:                  TradeState.OPEN,
            ipfsReceiptHash:        "",
            lockedAt:               0,
            paidAt:                 0,
            challengedAt:           0,
            cancelProposedByMaker:  false,
            cancelProposedByTaker:  false,
            pingedAt:               0,
            pingedByTaker:          false,
            challengePingedAt:      0,
            challengePingedByMaker: false
        });

        // ── Interactions ──
        IERC20(_token).safeTransferFrom(msg.sender, address(this), totalLock);
        emit EscrowCreated(tradeId, msg.sender, _token, _cryptoAmount, _tier);
    }

    // ═══════════════════════════════════════════════════
    //  MAKER AKIŞI — OPEN Escrow İptali
    //  MAKER FLOW — Cancel OPEN Escrow
    // ═══════════════════════════════════════════════════

    /**
     * @notice Eşleşmemiş (OPEN) ilanı iptal eder. Tüm fonlar maker'a iade edilir.
     * @notice Cancel a listing with no taker yet. Full refund to maker.
     * @param  _tradeId  Trade ID
     */
    function cancelOpenEscrow(uint256 _tradeId)
        external
        nonReentrant
        inState(_tradeId, TradeState.OPEN)
    {
        Trade storage t = trades[_tradeId];
        if (msg.sender != t.maker) revert OnlyMaker();

        uint256 refundAmount = t.cryptoAmount + t.makerBond;

        // ── Effects (CEI) ──
        t.state = TradeState.CANCELED;
        emit EscrowCanceled(_tradeId, refundAmount, 0);

        // ── Interactions ──
        IERC20(t.tokenAddress).safeTransfer(t.maker, refundAmount);
    }

    // ═══════════════════════════════════════════════════
    //  TAKER AKIŞI — Escrow Kilitleme (Anti-Sybil Kalkanı)
    //  TAKER FLOW — Lock Escrow (Anti-Sybil Shield)
    // ═══════════════════════════════════════════════════

    /**
     * @notice Taker ilanı kabul eder ve teminatını kilitler. Tüm Anti-Sybil kontrolleri çalışır.
     * @notice Taker matches a listing and locks bond. Full Anti-Sybil checks run here.
     * @param  _tradeId  Hedef trade ID / target trade ID
     */
    function lockEscrow(uint256 _tradeId)
        external
        nonReentrant
        notBanned
        whenNotPaused
        inState(_tradeId, TradeState.OPEN)
    {
        Trade storage t = trades[_tradeId];

        // ── Anti-Sybil Kontrolleri / Anti-Sybil Checks ──
        if (msg.sender == t.maker) revert SelfTradeForbidden();
        if (walletRegisteredAt[msg.sender] == 0 ||
            block.timestamp < walletRegisteredAt[msg.sender] + WALLET_AGE_MIN) {
            revert WalletTooYoung();
        }
        if (msg.sender.balance < DUST_LIMIT) revert InsufficientNativeBalance();
        if (t.tier == 0 || t.tier == 1) {
            if (lastTradeAt[msg.sender] != 0 &&
                block.timestamp < lastTradeAt[msg.sender] + TIER0_TRADE_COOLDOWN) {
                revert TierCooldownActive();
            }
        }

        uint8 takerEffectiveTier = _getEffectiveTier(msg.sender);
        if (t.tier > takerEffectiveTier) revert TierNotAllowed();

        uint256 takerBondBps = _getTakerBondBps(msg.sender, t.tier);
        uint256 takerBond    = (t.cryptoAmount * takerBondBps) / BPS_DENOMINATOR;

        // ── Effects ──
        t.taker     = msg.sender;
        t.takerBond = takerBond;
        t.state     = TradeState.LOCKED;
        t.lockedAt  = block.timestamp;
        lastTradeAt[msg.sender] = block.timestamp;

        // ── Interactions ──
        if (takerBond > 0) {
            IERC20(t.tokenAddress).safeTransferFrom(msg.sender, address(this), takerBond);
        }
        emit EscrowLocked(_tradeId, msg.sender, takerBond);
    }

    // ═══════════════════════════════════════════════════
    //  TAKER AKIŞI — Ödeme Bildirme
    //  TAKER FLOW — Report Payment
    // ═══════════════════════════════════════════════════

    /**
     * @notice Taker fiat ödemeyi yaptığını bildirir (IPFS dekont hash'i ile). 48s grace başlar.
     * @notice Taker reports off-chain fiat payment with IPFS receipt. 48h grace starts.
     * @param  _tradeId   Trade ID
     * @param  _ipfsHash  Ödeme dekontu IPFS hash'i / IPFS hash of payment receipt
     */
    function reportPayment(uint256 _tradeId, string calldata _ipfsHash)
        external
        nonReentrant
        inState(_tradeId, TradeState.LOCKED)
    {
        Trade storage t = trades[_tradeId];
        if (msg.sender != t.taker) revert OnlyTaker();
        if (bytes(_ipfsHash).length == 0) revert EmptyIpfsHash();

        t.state           = TradeState.PAID;
        t.paidAt          = block.timestamp;
        t.ipfsReceiptHash = _ipfsHash;
        emit PaymentReported(_tradeId, _ipfsHash, block.timestamp);
    }

    // ═══════════════════════════════════════════════════
    //  MAKER AKIŞI — Fon Serbest Bırakma (Normal Yol)
    //  MAKER FLOW — Release Funds (Happy Path)
    // ═══════════════════════════════════════════════════

    /**
     * @notice Maker ödemeyi onaylar ve USDT'yi Taker'a serbest bırakır.
     *         Bleeding aşamasında da çağrılabilir.
     * @notice Maker confirms receipt and releases USDT to Taker.
     *         Can also be called during Bleeding phase.
     *
     * Fee dağılımı / fee breakdown:
     *   takerFee  = cryptoAmount × TAKER_FEE_BPS → taker alacağından kesilir
     *   makerFee  = cryptoAmount × MAKER_FEE_BPS → maker bond'undan kesilir
     *   Toplam %0.2/işlem her iki taraftan %0.1'er
     *
     * @param  _tradeId  Trade ID
     */
    function releaseFunds(uint256 _tradeId)
        external
        nonReentrant
    {
        Trade storage t = trades[_tradeId];
        if (t.state != TradeState.PAID && t.state != TradeState.CHALLENGED) revert CannotReleaseInState();
        if (msg.sender != t.maker) revert OnlyMaker();

        (uint256 currentCrypto, uint256 currentMakerBond, uint256 currentTakerBond, uint256 decayed) =
            _calculateCurrentAmounts(_tradeId);

        // [TR] Reputation kararı state değişiminden ÖNCE alınmalı
        // [EN] Dispute flag must be captured before state change
        bool makerOpenedDispute = (t.state == TradeState.CHALLENGED);

        // ── Effects ──
        t.state = TradeState.RESOLVED;

        // ── Interactions (CEI) ──
        if (decayed > 0) {
            IERC20(t.tokenAddress).safeTransfer(treasury, decayed);
            emit BleedingDecayed(_tradeId, decayed, block.timestamp);
        }

        uint256 takerFee      = (currentCrypto * TAKER_FEE_BPS) / BPS_DENOMINATOR;
        uint256 takerReceives = currentCrypto - takerFee;

        uint256 makerFee          = (currentCrypto * MAKER_FEE_BPS) / BPS_DENOMINATOR;
        uint256 makerBondAfterFee = currentMakerBond > makerFee ? currentMakerBond - makerFee : 0;
        uint256 actualMakerFee    = currentMakerBond > makerFee ? makerFee : currentMakerBond;

        IERC20(t.tokenAddress).safeTransfer(t.taker, takerReceives);
        if (takerFee + actualMakerFee > 0) {
            IERC20(t.tokenAddress).safeTransfer(treasury, takerFee + actualMakerFee);
        }
        if (makerBondAfterFee > 0) {
            IERC20(t.tokenAddress).safeTransfer(t.maker, makerBondAfterFee);
        }
        if (currentTakerBond > 0) {
            IERC20(t.tokenAddress).safeTransfer(t.taker, currentTakerBond);
        }

        _updateReputation(t.maker, makerOpenedDispute);
        _updateReputation(t.taker, false);

        emit EscrowReleased(_tradeId, t.maker, t.taker, takerFee, actualMakerFee);
    }

    // ═══════════════════════════════════════════════════
    //  MAKER AKIŞI — Taker'ı Uyar (Challenge Öncesi)
    //  MAKER FLOW — Ping Taker (Pre-Challenge Warning)
    // ═══════════════════════════════════════════════════

    /**
     * @notice Maker, 24 saat sonra hâlâ ödeme gelmemişse Taker'a "ödeme gelmedi" uyarısı gönderir.
     *         challengeTrade için zorunlu ön koşuldur; Taker'a 24 saatlik yanıt penceresi açar.
     * @notice Maker warns Taker "payment not received" after 24h.
     *         Required prerequisite for challengeTrade; opens a 24h response window.
     * @param  _tradeId  Trade ID
     */
    function pingTakerForChallenge(uint256 _tradeId)
        external
        nonReentrant
        inState(_tradeId, TradeState.PAID)
    {
        Trade storage t = trades[_tradeId];
        if (msg.sender != t.maker) revert OnlyMaker();
        if (block.timestamp < t.paidAt + 24 hours) revert PingCooldownNotElapsed(t.paidAt + 24 hours);
        if (t.challengePingedByMaker) revert AlreadyPinged();

        // [TR] Taker autoRelease yolunu başlattıysa Maker challenge yolunu açamaz (MEV koruması)
        // [EN] If Taker already started autoRelease path, Maker cannot open challenge (MEV protection)
        if (t.pingedByTaker) revert ConflictingPingPath();

        t.challengePingedByMaker = true;
        t.challengePingedAt      = block.timestamp;
        emit MakerPinged(_tradeId, msg.sender, block.timestamp);
    }

    // ═══════════════════════════════════════════════════
    //  MAKER AKIŞI — Anlaşmazlık Başlatma
    //  MAKER FLOW — Open Dispute (Challenge)
    // ═══════════════════════════════════════════════════

    /**
     * @notice Maker itiraz sürecini başlatır. Grace Period (48s) açılır, Bleeding Escrow devreye girer.
     *         pingTakerForChallenge çağrısı ve 24s bekleme zorunludur.
     * @notice Maker opens a dispute. Enters Grace Period (48h), Bleeding Escrow activates.
     *         Requires prior pingTakerForChallenge call and 24h wait.
     * @param  _tradeId  Trade ID
     */
    function challengeTrade(uint256 _tradeId)
        external
        nonReentrant
        inState(_tradeId, TradeState.PAID)
    {
        Trade storage t = trades[_tradeId];
        if (msg.sender != t.maker) revert OnlyMaker();
        if (!t.challengePingedByMaker) revert MustPingFirst();
        if (block.timestamp < t.challengePingedAt + 24 hours) revert ResponseWindowActive();

        t.state       = TradeState.CHALLENGED;
        t.challengedAt = block.timestamp;
        emit DisputeOpened(_tradeId, msg.sender, block.timestamp);
    }

    // ═══════════════════════════════════════════════════
    //  KARŞILIKLI İPTAL — EIP-712 İmza Tabanlı
    //  COLLABORATIVE CANCEL — EIP-712 Signature Based
    // ═══════════════════════════════════════════════════

    /**
     * @notice EIP-712 imzalı karşılıklı iptal teklifini sunar veya onaylar.
     *         İlk çağıran teklif eder; ikincisi (karşı taraf) onaylayarak işlemi tamamlar.
     * @notice Propose or approve a collaborative cancel via EIP-712 signatures.
     *         First caller proposes; second caller (other party) finalizes.
     * @param  _tradeId   Trade ID
     * @param  _deadline  İmza son geçerlilik tarihi / signature expiry
     * @param  _sig       EIP-712 imzası / EIP-712 signature
     */
    function proposeOrApproveCancel(
        uint256 _tradeId,
        uint256 _deadline,
        bytes calldata _sig
    ) external nonReentrant {
        Trade storage t = trades[_tradeId];

        if (t.state != TradeState.LOCKED &&
            t.state != TradeState.PAID &&
            t.state != TradeState.CHALLENGED) revert CannotReleaseInState();
        if (block.timestamp > _deadline) revert SignatureExpired();
        if (msg.sender != t.maker && msg.sender != t.taker) revert NotTradeParty();

        // [TR] Deadline üst sınırı — backend bypass koruması
        // [EN] Deadline cap — protects against direct contract calls bypassing backend
        if (_deadline > block.timestamp + MAX_CANCEL_DEADLINE) revert DeadlineTooFar();

        bytes32 structHash = keccak256(abi.encode(
            CANCEL_TYPEHASH,
            _tradeId,
            msg.sender,
            sigNonces[msg.sender],
            _deadline
        ));

        bytes32 digest    = _hashTypedDataV4(structHash);
        address recovered = ECDSA.recover(digest, _sig);
        if (recovered != msg.sender) revert InvalidSignature();

        sigNonces[msg.sender]++;

        if (msg.sender == t.maker) t.cancelProposedByMaker = true;
        else                       t.cancelProposedByTaker = true;

        emit CancelProposed(_tradeId, msg.sender);

        if (t.cancelProposedByMaker && t.cancelProposedByTaker) {
            _executeCancel(_tradeId);
        }
    }

    // ═══════════════════════════════════════════════════
    //  BURN — 10 Günlük Timeout
    //  BURN — 10-Day Timeout
    // ═══════════════════════════════════════════════════

    /**
     * @notice 10 günlük Bleeding süresi dolduktan sonra herkes burn'ü tetikleyebilir.
     *         Kalan tüm fonlar hazineye gider. Her iki taraf da reputation cezası alır.
     * @notice Anyone can trigger burn after 10-day Bleeding timeout.
     *         All remaining funds go to treasury. Both parties receive reputation penalty.
     * @param  _tradeId  Trade ID
     */
    function burnExpired(uint256 _tradeId)
        external
        nonReentrant
        inState(_tradeId, TradeState.CHALLENGED)
    {
        Trade storage t = trades[_tradeId];
        if (block.timestamp < t.challengedAt + MAX_BLEEDING) revert BurnPeriodNotReached();

        (uint256 currentCrypto, uint256 currentMakerBond, uint256 currentTakerBond,) =
            _calculateCurrentAmounts(_tradeId);

        uint256 totalBurn = currentCrypto + currentMakerBond + currentTakerBond;

        t.state = TradeState.BURNED;

        if (totalBurn > 0) {
            IERC20(t.tokenAddress).safeTransfer(treasury, totalBurn);
        }

        _updateReputation(t.maker, true);
        _updateReputation(t.taker, true);

        emit EscrowBurned(_tradeId, totalBurn);
    }

    // ═══════════════════════════════════════════════════
    //  TAKER AKIŞI — Maker'ı Uyar (Hayatta Mısın?)
    //  TAKER FLOW — Ping Maker (Liveness Check)
    // ═══════════════════════════════════════════════════

    /**
     * @notice Taker, ödeme bildirildikten 48 saat sonra hâlâ yanıt vermeyen Maker'a uyarı gönderir.
     *         autoRelease için zorunlu ön koşuldur.
     * @notice Taker sends liveness check to inactive Maker after 48h.
     *         Required prerequisite for autoRelease.
     * @param  _tradeId  Trade ID
     */
    function pingMaker(uint256 _tradeId)
        external
        nonReentrant
        inState(_tradeId, TradeState.PAID)
    {
        Trade storage t = trades[_tradeId];
        if (msg.sender != t.taker) revert OnlyTaker();
        if (block.timestamp < t.paidAt + GRACE_PERIOD) revert PingCooldownNotElapsed(t.paidAt + GRACE_PERIOD);
        if (t.pingedByTaker) revert AlreadyPinged();

        // [TR] Maker challenge yolunu başlattıysa Taker autoRelease yolunu açamaz (MEV koruması)
        // [EN] If Maker already started challenge path, Taker cannot open autoRelease (MEV protection)
        if (t.challengePingedByMaker) revert ConflictingPingPath();

        t.pingedByTaker = true;
        t.pingedAt      = block.timestamp;
        emit MakerPinged(_tradeId, msg.sender, block.timestamp);
    }

    // ═══════════════════════════════════════════════════
    //  OTOMATİK SERBEST BIRAKMA — 48s Grace Timeout (Taker Fallback)
    //  AUTO-RELEASE — 48h Grace Period Timeout (Taker Fallback)
    // ═══════════════════════════════════════════════════

    /**
     * @notice Ping'den 24 saat sonra Maker hâlâ yanıt vermemişse Taker fonları serbest bırakır.
     *         Her iki tarafın teminatından %2 ihmal cezası kesilir.
     * @notice If Maker doesn't respond 24h after ping, Taker can self-release.
     *         2% negligence penalty deducted from both bonds.
     * @param  _tradeId  Trade ID
     */
    function autoRelease(uint256 _tradeId)
        external
        nonReentrant
        inState(_tradeId, TradeState.PAID)
    {
        Trade storage t = trades[_tradeId];
        if (msg.sender != t.taker) revert OnlyTaker();
        if (!t.pingedByTaker) revert MustPingFirst();
        if (block.timestamp < t.pingedAt + 24 hours) revert ResponseWindowActive();

        (uint256 currentCrypto, uint256 currentMakerBond, uint256 currentTakerBond, uint256 decayed) =
            _calculateCurrentAmounts(_tradeId);

        t.state = TradeState.RESOLVED;

        if (decayed > 0) {
            IERC20(t.tokenAddress).safeTransfer(treasury, decayed);
            emit BleedingDecayed(_tradeId, decayed, block.timestamp);
        }

        uint256 makerPenalty     = (currentMakerBond * AUTO_RELEASE_PENALTY_BPS) / BPS_DENOMINATOR;
        uint256 takerPenalty     = (currentTakerBond * AUTO_RELEASE_PENALTY_BPS) / BPS_DENOMINATOR;
        uint256 makerReceives    = currentMakerBond - makerPenalty;
        uint256 takerReceivesBond = currentTakerBond - takerPenalty;
        uint256 totalPenalty     = makerPenalty + takerPenalty;

        IERC20(t.tokenAddress).safeTransfer(t.taker, currentCrypto);
        if (makerReceives > 0)    IERC20(t.tokenAddress).safeTransfer(t.maker, makerReceives);
        if (takerReceivesBond > 0) IERC20(t.tokenAddress).safeTransfer(t.taker, takerReceivesBond);
        if (totalPenalty > 0)     IERC20(t.tokenAddress).safeTransfer(treasury, totalPenalty);

        _updateReputation(t.maker, true);
        _updateReputation(t.taker, false);

        emit EscrowReleased(_tradeId, t.maker, t.taker, makerPenalty, takerPenalty);
    }

    // ═══════════════════════════════════════════════════
    //  İÇ YARDIMCILAR / INTERNAL HELPERS
    // ═══════════════════════════════════════════════════

    /**
     * @dev Karşılıklı iptal işlemini yürütür ve iadeleri hesaplar.
     *      LOCKED'da iptal → fee yok. PAID/CHALLENGED'da iptal → %0.2 fee kesilir.
     * @dev Executes mutual cancel and calculates refunds.
     *      Cancel in LOCKED → no fee. Cancel in PAID/CHALLENGED → 0.2% fee.
     */
    function _executeCancel(uint256 _tradeId) internal {
        Trade storage t = trades[_tradeId];
        TradeState currentState = t.state;

        (uint256 currentCrypto, uint256 currentMakerBond, uint256 currentTakerBond, uint256 decayed) =
            _calculateCurrentAmounts(_tradeId);

        t.state = TradeState.CANCELED;

        if (decayed > 0) {
            IERC20(t.tokenAddress).safeTransfer(treasury, decayed);
            emit BleedingDecayed(_tradeId, decayed, block.timestamp);
        }

        uint256 takerFee = 0;
        uint256 makerFee = 0;

        // [TR] Ödeme bildirildiyse protokol fee'si kesilir (sistemi meşgul ettikleri için)
        // [EN] Fee charged only if payment was reported (they occupied protocol resources)
        if (currentState == TradeState.PAID || currentState == TradeState.CHALLENGED) {
            takerFee = (currentCrypto * TAKER_FEE_BPS) / BPS_DENOMINATOR;
            makerFee = (currentCrypto * MAKER_FEE_BPS) / BPS_DENOMINATOR;
        }

        uint256 totalFeeToTreasury = 0;
        uint256 makerRefund;
        uint256 takerRefund;

        if (currentMakerBond >= makerFee) {
            makerRefund = currentCrypto + (currentMakerBond - makerFee);
            totalFeeToTreasury += makerFee;
        } else {
            makerRefund = currentCrypto;
            totalFeeToTreasury += currentMakerBond;
        }

        if (currentTakerBond >= takerFee) {
            takerRefund = currentTakerBond - takerFee;
            totalFeeToTreasury += takerFee;
        } else {
            takerRefund = 0;
            totalFeeToTreasury += currentTakerBond;
        }

        if (totalFeeToTreasury > 0) IERC20(t.tokenAddress).safeTransfer(treasury, totalFeeToTreasury);
        if (makerRefund > 0)        IERC20(t.tokenAddress).safeTransfer(t.maker, makerRefund);
        if (takerRefund > 0)        IERC20(t.tokenAddress).safeTransfer(t.taker, takerRefund);

        emit EscrowCanceled(_tradeId, makerRefund, takerRefund);
    }

    /**
     * @dev Bleeding Escrow sistemine göre saniye bazlı güncel fon miktarını hesaplar.
     *      Saniye bazlı formül: decayed = amount * rateBpsH * seconds / (10000 * 3600)
     *      Bu yaklaşım, saatlik integer bölmesinin neden olduğu step-function sorununu giderir.
     * @dev Calculates current amounts after Bleeding Escrow decay.
     *      Second-based formula: decayed = amount * rateBpsH * seconds / (10000 * 3600)
     *      Eliminates step-function issue caused by hourly integer division.
     *
     * Overflow analizi (uint256 güvenli / safe):
     *   Max cryptoAmount: ~10^12 (1B USDT 6 decimal)
     *   Max rate×2: 68, Max elapsedSeconds: 691200 (192h)
     *   Çarpım: 10^12 × 68 × 691200 = 4.7 × 10^19 ≪ 2^256
     */
    function _calculateCurrentAmounts(uint256 _tradeId)
        internal
        view
        returns (
            uint256 currentCrypto,
            uint256 currentMakerBond,
            uint256 currentTakerBond,
            uint256 totalDecayed
        )
    {
        Trade storage t = trades[_tradeId];

        if (t.state != TradeState.CHALLENGED || t.challengedAt == 0) {
            return (t.cryptoAmount, t.makerBond, t.takerBond, 0);
        }

        uint256 elapsed = block.timestamp - t.challengedAt;
        if (elapsed > MAX_BLEEDING) elapsed = MAX_BLEEDING;

        uint256 bleedingElapsed = elapsed > GRACE_PERIOD ? elapsed - GRACE_PERIOD : 0;

        uint256 makerBondDecayed = (t.makerBond * MAKER_BOND_DECAY_BPS_H * bleedingElapsed) / (BPS_DENOMINATOR * SECONDS_PER_HOUR);
        if (makerBondDecayed > t.makerBond) makerBondDecayed = t.makerBond;

        uint256 takerBondDecayed = (t.takerBond * TAKER_BOND_DECAY_BPS_H * bleedingElapsed) / (BPS_DENOMINATOR * SECONDS_PER_HOUR);
        if (takerBondDecayed > t.takerBond) takerBondDecayed = t.takerBond;

        currentMakerBond = t.makerBond - makerBondDecayed;
        currentTakerBond = t.takerBond - takerBondDecayed;

        // [TR] Crypto erimesi USDT_DECAY_START'tan (grace bittikten 96s sonra) başlar
        // [EN] Crypto decay starts after USDT_DECAY_START (96h after grace ends)
        uint256 cryptoDecayed = 0;
        if (bleedingElapsed > USDT_DECAY_START) {
            uint256 usdtElapsed = bleedingElapsed - USDT_DECAY_START;
            cryptoDecayed = (t.cryptoAmount * CRYPTO_DECAY_BPS_H * 2 * usdtElapsed) / (BPS_DENOMINATOR * SECONDS_PER_HOUR);
            if (cryptoDecayed > t.cryptoAmount) cryptoDecayed = t.cryptoAmount;
        }

        currentCrypto = t.cryptoAmount - cryptoDecayed;
        totalDecayed  = makerBondDecayed + takerBondDecayed + cryptoDecayed;
    }

    /**
     * @dev Maker'ın itibar durumuna göre teminat oranını (BPS) döndürür.
     * @dev Returns maker bond BPS adjusted for reputation.
     */
    function _getMakerBondBps(address _maker, uint8 _tier)
        internal
        view
        returns (uint256 bondBps)
    {
        if      (_tier == 0) return MAKER_BOND_TIER0_BPS;
        else if (_tier == 1) bondBps = MAKER_BOND_TIER1_BPS;
        else if (_tier == 2) bondBps = MAKER_BOND_TIER2_BPS;
        else if (_tier == 3) bondBps = MAKER_BOND_TIER3_BPS;
        else                 bondBps = MAKER_BOND_TIER4_BPS;

        Reputation storage rep = reputation[_maker];
        if (rep.failedDisputes == 0 && rep.successfulTrades > 0) {
            bondBps = bondBps > GOOD_REP_DISCOUNT_BPS ? bondBps - GOOD_REP_DISCOUNT_BPS : 0;
        } else if (rep.failedDisputes >= 1) {
            bondBps += BAD_REP_PENALTY_BPS;
        }
    }

    /**
     * @dev Taker'ın itibar durumuna göre teminat oranını (BPS) döndürür.
     * @dev Returns taker bond BPS adjusted for reputation.
     */
    function _getTakerBondBps(address _taker, uint8 _tier)
        internal
        view
        returns (uint256 bondBps)
    {
        if      (_tier == 0) return TAKER_BOND_TIER0_BPS;
        else if (_tier == 1) bondBps = TAKER_BOND_TIER1_BPS;
        else if (_tier == 2) bondBps = TAKER_BOND_TIER2_BPS;
        else if (_tier == 3) bondBps = TAKER_BOND_TIER3_BPS;
        else                 bondBps = TAKER_BOND_TIER4_BPS;

        Reputation storage rep = reputation[_taker];
        if (rep.failedDisputes == 0 && rep.successfulTrades > 0) {
            bondBps = bondBps > GOOD_REP_DISCOUNT_BPS ? bondBps - GOOD_REP_DISCOUNT_BPS : 0;
        } else if (rep.failedDisputes >= 1) {
            bondBps += BAD_REP_PENALTY_BPS;
        }
    }

    /**
     * @dev Kullanıcının on-chain itibar puanlarını günceller ve gerekirse ceza uygular.
     *
     *      Ban mekanizması (2+ failedDispute tetikler):
     *        1. ban → 30 gün,  consecutiveBans = 1
     *        2. ban → 60 gün,  consecutiveBans = 2 + tier 1 düşer
     *        3. ban → 120 gün, consecutiveBans = 3 + tier 1 daha düşer
     *        Her ban süreyi ×2 yapar, tier 1 daha düşürür.
     *
     * @dev Updates on-chain reputation and applies bans/tier demotions if needed.
     *
     *      Ban mechanism (triggers at 2+ failedDisputes):
     *        1st ban → 30d,  consecutiveBans = 1
     *        2nd ban → 60d,  consecutiveBans = 2 + tier drops 1
     *        Each ban doubles duration and drops tier by 1.
     */
    function _updateReputation(address _wallet, bool _failed) internal {
        Reputation storage rep = reputation[_wallet];

        if (_failed) {
            rep.failedDisputes++;

            if (rep.failedDisputes >= 2) {
                rep.consecutiveBans++;

                uint256 banDays = 30 days * (2 ** (rep.consecutiveBans - 1));
                if (banDays > 365 days) banDays = 365 days;
                rep.bannedUntil = block.timestamp + banDays;

                if (rep.consecutiveBans >= 2) {
                    // [TR] İlk kez tier cezası → maxAllowedTier'ı 4'ten başlat (sentinel)
                    // [EN] First tier penalty → initialize maxAllowedTier at 4 (sentinel)
                    if (!hasTierPenalty[_wallet]) {
                        hasTierPenalty[_wallet] = true;
                        maxAllowedTier[_wallet] = 4;
                    }
                    if (maxAllowedTier[_wallet] > 0) {
                        maxAllowedTier[_wallet] = maxAllowedTier[_wallet] - 1;
                    }
                }
            }
        } else {
            rep.successfulTrades++;
            // [TR] İlk başarılı işlem zamanı bir kez set edilir — Sybil hızlı tier atlama caydırıcısı
            // [EN] First successful trade timestamp set once — deters Sybil fast-tier escalation
            if (firstSuccessfulTradeAt[_wallet] == 0) {
                firstSuccessfulTradeAt[_wallet] = block.timestamp;
            }
        }

        emit ReputationUpdated(
            _wallet,
            rep.successfulTrades,
            rep.failedDisputes,
            rep.bannedUntil,
            _getEffectiveTier(_wallet)
        );
    }

    // ═══════════════════════════════════════════════════
    //  İTİBAR SIFIRLAMA — Temiz Sayfa Kuralı
    //  REPUTATION DECAY — Clean Slate Rule
    // ═══════════════════════════════════════════════════

    /**
     * @notice Son yasak bittikten 180 gün sonra ardışık yasak sayacını sıfırlar.
     *         Herkes tarafından çağrılabilir (gazı çağıran öder).
     * @notice Resets consecutive ban counter after 180 clean days post-ban.
     *         Anyone can call (caller pays gas).
     * @param  _wallet  İtibarı sıfırlanacak cüzdan / wallet to reset
     */
    function decayReputation(address _wallet) external nonReentrant {
        Reputation storage rep = reputation[_wallet];
        if (rep.bannedUntil == 0) revert NoPriorBanHistory();
        if (block.timestamp <= rep.bannedUntil + 180 days) revert CleanPeriodNotElapsed();
        if (rep.consecutiveBans == 0) revert NoBansToReset();

        rep.consecutiveBans = 0;
        // [TR] maxAllowedTier ve hasTierPenalty sıfırlanmaz — kaybedilen tier'lar
        //      yeniden başarılı işlemler yapılarak _getEffectiveTier üzerinden kazanılır.
        // [EN] maxAllowedTier and hasTierPenalty are NOT reset — lost tiers must be
        //      re-earned through successful trades via _getEffectiveTier.

        emit ReputationUpdated(
            _wallet,
            rep.successfulTrades,
            rep.failedDisputes,
            rep.bannedUntil,
            _getEffectiveTier(_wallet)
        );
    }

    /**
     * @dev Kullanıcının itibar ve ceza durumuna göre efektif tier'ını hesaplar.
     *
     *      Tier eşikleri:
     *        T4: 200+ başarılı, ≤15 failed
     *        T3: 100+ başarılı, ≤10 failed
     *        T2:  50+ başarılı,  ≤5 failed
     *        T1:  15+ başarılı,  ≤2 failed
     *        T0:  Diğer tüm durumlar
     *
     *      MIN_ACTIVE_PERIOD: İlk başarılı işlemden 15 gün geçmeden Tier 1+ verilmez.
     *      hasTierPenalty sentinel: false → tavan yok; true → maxAllowedTier geçerli.
     *
     * @dev Calculates effective tier based on reputation and penalty state.
     *
     *      MIN_ACTIVE_PERIOD: No Tier 1+ access until 15 days after first successful trade.
     *      hasTierPenalty sentinel: false → no cap; true → maxAllowedTier applies.
     */
    function _getEffectiveTier(address _wallet) internal view returns (uint8) {
        Reputation storage rep = reputation[_wallet];
        uint8 calculatedTier;

        if      (rep.successfulTrades >= 200 && rep.failedDisputes <= 15) calculatedTier = 4;
        else if (rep.successfulTrades >= 100 && rep.failedDisputes <= 10) calculatedTier = 3;
        else if (rep.successfulTrades >=  50 && rep.failedDisputes <=  5) calculatedTier = 2;
        else if (rep.successfulTrades >=  15 && rep.failedDisputes <=  2) calculatedTier = 1;
        else                                                               calculatedTier = 0;

        if (calculatedTier > 0) {
            if (firstSuccessfulTradeAt[_wallet] == 0 ||
                block.timestamp < firstSuccessfulTradeAt[_wallet] + MIN_ACTIVE_PERIOD) {
                calculatedTier = 0;
            }
        }

        if (!hasTierPenalty[_wallet]) return calculatedTier;
        return calculatedTier > maxAllowedTier[_wallet] ? maxAllowedTier[_wallet] : calculatedTier;
    }

    /**
     * @dev Tier seviyesine göre maksimum işlem limitini döndürür. Tier 4 = 0 (limitsiz).
     * @dev Returns max crypto amount for a tier. Tier 4 = 0 (unlimited).
     */
    function _getTierMaxAmount(uint8 _tier) internal pure returns (uint256) {
        if (_tier == 0) return TIER_MAX_AMOUNT_TIER0;
        if (_tier == 1) return TIER_MAX_AMOUNT_TIER1;
        if (_tier == 2) return TIER_MAX_AMOUNT_TIER2;
        if (_tier == 3) return TIER_MAX_AMOUNT_TIER3;
        return 0; // Tier 4 = limitsiz / unlimited
    }

    // ═══════════════════════════════════════════════════
    //  GÖRÜNÜM FONKSİYONLARI / VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════

    /**
     * @notice Kullanıcının itibar ve ban detaylarını döndürür.
     * @notice Returns user reputation and ban details.
     */
    function getReputation(address _wallet)
        external
        view
        returns (
            uint256 successful,
            uint256 failed,
            uint256 bannedUntil,
            uint256 consecutiveBans,
            uint8   effectiveTier
        )
    {
        Reputation storage rep = reputation[_wallet];
        return (
            rep.successfulTrades,
            rep.failedDisputes,
            rep.bannedUntil,
            rep.consecutiveBans,
            _getEffectiveTier(_wallet)
        );
    }

    /**
     * @notice İlk başarılı işlem timestamp'ini döndürür.
     *         Frontend, MIN_ACTIVE_PERIOD geri sayımı için bunu kullanır.
     * @notice Returns timestamp of wallet's first successful trade.
     *         Used by frontend to calculate MIN_ACTIVE_PERIOD countdown.
     */
    function getFirstSuccessfulTradeAt(address _wallet) external view returns (uint256) {
        return firstSuccessfulTradeAt[_wallet];
    }

    /**
     * @notice Tier 0/1 cooldown kalan süresini saniye cinsinden döndürür.
     *         Frontend "neden işlem yapamıyorum?" sorusunu yanıtlamak için kullanır.
     * @notice Returns remaining Tier 0/1 cooldown in seconds.
     *         Lets frontend display why a user cannot trade yet (D-03 fix).
     */
    function getCooldownRemaining(address _wallet) external view returns (uint256) {
        uint256 last = lastTradeAt[_wallet];
        if (last == 0) return 0;
        uint256 cooldownEnd = last + TIER0_TRADE_COOLDOWN;
        if (block.timestamp >= cooldownEnd) return 0;
        return cooldownEnd - block.timestamp;
    }

    /**
     * @notice İşlemin tam detaylarını döndürür.
     *         Solidity auto-getter named field erişimi vermediğinden bu fonksiyon gereklidir.
     * @notice Returns full trade details.
     *         Needed because Solidity auto-getter returns a tuple without named field access.
     */
    function getTrade(uint256 _tradeId) external view returns (Trade memory) {
        return trades[_tradeId];
    }

    /**
     * @notice Bleeding Escrow sonrası anlık kalan miktarları döndürür.
     *         Frontend ve üçüncü taraflar decay miktarını on-chain'den okuyabilir.
     * @notice Returns current amounts after Bleeding Escrow decay.
     *         Allows frontend and third parties to read decay on-chain.
     */
    function getCurrentAmounts(uint256 _tradeId)
        external
        view
        returns (
            uint256 currentCrypto,
            uint256 currentMakerBond,
            uint256 currentTakerBond,
            uint256 totalDecayed
        )
    {
        return _calculateCurrentAmounts(_tradeId);
    }

    /**
     * @notice Cüzdanın Anti-Sybil (Tier 0/1) kontrolünden geçip geçmediğini gösterir.
     * @notice Check if wallet passes Anti-Sybil (Tier 0 and Tier 1).
     */
    function antiSybilCheck(address _wallet)
        external
        view
        returns (bool aged, bool funded, bool cooldownOk)
    {
        aged = walletRegisteredAt[_wallet] != 0 &&
               block.timestamp >= walletRegisteredAt[_wallet] + WALLET_AGE_MIN;

        funded = _wallet.balance >= DUST_LIMIT;

        cooldownOk = lastTradeAt[_wallet] == 0 ||
                     block.timestamp >= lastTradeAt[_wallet] + TIER0_TRADE_COOLDOWN;
    }

    /**
     * @notice Frontend imzalama için EIP-712 domain separator'ı döndürür.
     * @notice Returns EIP-712 domain separator for frontend signing.
     */
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ═══════════════════════════════════════════════════
    //  YÖNETİM — Sadece Owner
    //  ADMIN — Owner Only
    // ═══════════════════════════════════════════════════

    function setTreasury(address _treasury) external onlyOwner {
        if (_treasury == address(0)) revert OwnableInvalidOwner(address(0));
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }

    /**
     * @notice Desteklenen token ekler veya çıkarır.
     *         supportedTokens mapping'i güncellenir — önceki versiyonda bu satır eksikti.
     * @notice Add or remove a supported token.
     *         Correctly updates the supportedTokens mapping.
     */
    function setSupportedToken(address _token, bool _supported) external onlyOwner {
        if (_token == address(0)) revert OwnableInvalidOwner(address(0));
        supportedTokens[_token] = _supported;
        emit TokenSupportUpdated(_token, _supported);
    }

    // [TR] pause → sadece createEscrow ve lockEscrow'u etkiler (whenNotPaused).
    //      releaseFunds, autoRelease, burnExpired, proposeOrApproveCancel pause'da da çalışır —
    //      bu kasıtlı: mevcut işlemlerin sonlandırılabilmesi gerekir.
    // [EN] pause → only affects createEscrow and lockEscrow (whenNotPaused).
    //      releaseFunds, autoRelease, burnExpired, proposeOrApproveCancel still work while paused —
    //      by design: existing trades must be closeable during an emergency.
    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
