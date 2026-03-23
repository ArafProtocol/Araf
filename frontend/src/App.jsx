import React, { useState, useEffect } from 'react';
import { useAccount, useConnect, useDisconnect, useSignMessage, useChainId, usePublicClient } from 'wagmi';
import { SiweMessage } from 'siwe';
import { useArafContract } from './hooks/useArafContract';
import { useCountdown } from './hooks/useCountdown';
import PIIDisplay from './components/PIIDisplay';

// ─────────────────────────────────────────────
// [TR] API URL: DEV modunda localhost, prod'da VITE_API_URL zorunlu
// [EN] API URL: localhost in DEV, VITE_API_URL required in prod
// ─────────────────────────────────────────────
const API_URL = import.meta.env.VITE_API_URL || (
  import.meta.env.DEV ? 'http://localhost:4000' : ''
);

// [TR] Uygulama başlangıcında kritik env değişkenlerini doğrula
// [EN] Validate critical env variables on app start
const ENV_ERRORS = [];
if (!import.meta.env.VITE_API_URL && import.meta.env.PROD) {
  ENV_ERRORS.push('VITE_API_URL tanımlı değil — API çağrıları çalışmayacak');
}
if (!import.meta.env.VITE_ESCROW_ADDRESS ||
    import.meta.env.VITE_ESCROW_ADDRESS === '0x0000000000000000000000000000000000000000') {
  ENV_ERRORS.push('VITE_ESCROW_ADDRESS tanımlı değil veya sıfır adres — kontrat işlemleri çalışmayacak');
}

// [TR] Eksik env değişkenleri için kapatılabilir uyarı şeridi
// [EN] Dismissible warning strip for missing env variables
const EnvWarningBanner = () => {
  const [visible, setVisible] = React.useState(true);
  if (ENV_ERRORS.length === 0 || !visible) return null;
  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-red-950/95 border-b border-red-800/60 backdrop-blur-sm flex items-center justify-between px-4 py-1.5 shadow-lg">
      <span className="text-red-400 text-[11px] font-mono flex items-center gap-2">
        <span className="text-red-500">⚠</span>
        {ENV_ERRORS.join(' · ')}
      </span>
      <button
        onClick={() => setVisible(false)}
        className="ml-4 text-red-500 hover:text-white transition text-sm leading-none shrink-0"
        aria-label="Kapat"
      >✕</button>
    </div>
  );
};

// [TR] İstatistik kartlarındaki 30 günlük değişim yüzdesi göstergesi
// [EN] 30-day change percentage indicator for stat cards
const StatChange = ({ value }) => {
  if (value == null) return null;
  const isPositive = value >= 0;
  return <span className={`text-[10px] ml-2 font-bold ${isPositive ? 'text-emerald-400' : 'text-red-400'}`}>{isPositive ? '▲' : '▼'}{Math.abs(value).toFixed(1)}%</span>;
};

function App() {
  // ═══════════════════════════════════════════
  // 1. EKRAN VE UI STATE YÖNETİMİ
  //    View routing + modal open/close flags
  // ═══════════════════════════════════════════
  const [currentView, setCurrentView] = useState('home');
  const [showMakerModal, setShowMakerModal] = useState(false);
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [showFeedbackModal, setShowFeedbackModal] = useState(false);
  const [showWalletModal, setShowWalletModal] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [expandedStatus, setExpandedStatus] = useState(null);

  // [TR] Sidebar 5 sn otomatik kapanma timer referansı
  // [EN] Sidebar auto-close timer ref (resets on hover)
  const sidebarTimerRef = React.useRef(null);

  // [TR] Geliştirme / demo amaçlı trade state toggle'ları
  // [EN] Dev/demo trade state toggles
  const [tradeState, setTradeState] = useState('LOCKED');
  const [userRole, setUserRole] = useState('taker');
  const [isBanned, setIsBanned] = useState(false);
  const [cancelStatus, setCancelStatus] = useState(null);
  const [cooldownPassed, setCooldownPassed] = useState(false);
  const [chargebackAccepted, setChargebackAccepted] = useState(false);

  // [TR] Maker ilan formu state'leri
  // [EN] Maker listing form states
  const [makerTier, setMakerTier]         = useState(1);
  const [makerAmount, setMakerAmount]     = useState('');
  const [makerRate, setMakerRate]         = useState('');
  const [makerMinLimit, setMakerMinLimit] = useState('');
  const [makerMaxLimit, setMakerMaxLimit] = useState('');
  const [makerFiat, setMakerFiat]         = useState('TRY');

  // [TR] Desteklenen token adresleri — .env üzerinden yönetilir
  // [EN] Supported token addresses — managed via .env
  const SUPPORTED_TOKEN_ADDRESSES = {
    USDT: import.meta.env.VITE_USDT_ADDRESS || '',
    USDC: import.meta.env.VITE_USDC_ADDRESS || '',
  };
  const [makerToken, setMakerToken] = useState('USDT');

  // ═══════════════════════════════════════════
  // 2. WEB3 BAĞLANTI VE KONTRAT HOOK'LARI
  //    Wallet connection + all contract methods
  // ═══════════════════════════════════════════
  const { address, isConnected } = useAccount();
  const { connect, connectors } = useConnect();
  const { disconnect } = useDisconnect();
  const { signMessageAsync } = useSignMessage();
  const chainId = useChainId();
  const publicClient = usePublicClient();

  // [TR] Tüm kontrat metodları tek bir hook instance'ından alınır
  // [EN] All contract methods come from a single hook instance
  const {
    releaseFunds,
    challengeTrade,
    autoRelease,
    pingMaker,
    pingTakerForChallenge,
    lockEscrow,
    cancelOpenEscrow,
    signCancelProposal,
    proposeOrApproveCancel,
    getReputation,
    getCurrentAmounts,
    createEscrow,
    registerWallet,
    reportPayment,
    burnExpired,
    approveToken,
    getAllowance,
    getTrade,
    getPaused,
    decayReputation,
    antiSybilCheck,
    mintToken,
    getFirstSuccessfulTradeAt,
  } = useArafContract();

  // ═══════════════════════════════════════════
  // 3. KİMLİK DOĞRULAMA STATE'LERİ
  //    Auth + wallet registration status
  // ═══════════════════════════════════════════
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);

  // [TR] Cüzdan on-chain kayıt durumu — null: bilinmiyor, true/false: kayıtlı/değil
  // [EN] Wallet on-chain registration status — null: unknown, true/false: registered/not
  const [isWalletRegistered, setIsWalletRegistered] = useState(null);
  const [isRegisteringWallet, setIsRegisteringWallet] = useState(false);

  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // [TR] Kontrat işlemleri sırasında çift tıklamayı önleme ve iki aşamalı UX için
  // [EN] Prevents double-clicks during contract tx; shows two-phase loading text
  const [isContractLoading, setIsContractLoading] = useState(false);
  const [loadingText, setLoadingText] = useState('');

  // ═══════════════════════════════════════════
  // 4. KULLANICI TERCİHLERİ VE VERİ STATE'LERİ
  //    Language, filters, PII form, reputation
  // ═══════════════════════════════════════════
  const [lang, setLang] = useState('EN');
  const [filterTier1, setFilterTier1] = useState(false);
  const [filterToken, setFilterToken] = useState('ALL');
  const [activeTradesFilter, setActiveTradesFilter] = useState('ALL');
  const [searchAmount, setSearchAmount] = useState('');
  const [profileTab, setProfileTab] = useState('ayarlar');

  const [userReputation, setUserReputation] = useState(null);
  const [piiBankOwner, setPiiBankOwner] = useState('');
  const [piiIban, setPiiIban] = useState('');
  const [piiTelegram, setPiiTelegram] = useState('');

  const [tradeHistory, setTradeHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [tradeHistoryPage, setTradeHistoryPage] = useState(1);
  const [tradeHistoryTotal, setTradeHistoryTotal] = useState(0);
  const [tradeHistoryLimit, setTradeHistoryLimit] = useState(10);

  // [TR] Aktif işlem ve ödeme kanıtı hash state'leri
  // [EN] Active trade and payment proof hash states
  const [activeTrade, setActiveTrade] = useState(null);
  const [paymentIpfsHash, setPaymentIpfsHash] = useState('');

  const [sybilStatus, setSybilStatus] = useState(null);
  const [takerName, setTakerName] = useState('');

  const [isPaused, setIsPaused] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(localStorage.getItem('araf_terms_accepted') === 'true');

  const [feedbackText, setFeedbackText] = useState('');
  const [feedbackRating, setFeedbackRating] = useState(0);
  const [feedbackCategory, setFeedbackCategory] = useState('');

  // [TR] Protokol istatistikleri — /api/stats endpoint'inden çekilir
  // [EN] Protocol stats — fetched from /api/stats endpoint
  const [protocolStats, setProtocolStats] = useState(null);
  const [statsLoading, setStatsLoading]   = useState(true);
  const [statsError, setStatsError] = useState(false);

  // [TR] On-chain bond oranları — tier bazında maker/taker BPS değerleri
  // [EN] On-chain bond rates — maker/taker BPS values per tier
  const [onchainBondMap, setOnchainBondMap] = useState(null);

  // [TR] CHALLENGED aşamasında teminat erime miktarları
  // [EN] Collateral decay amounts in CHALLENGED phase
  const [bleedingAmounts, setBleedingAmounts] = useState(null);

  const [orders, setOrders] = useState([]);
  const [activeEscrows, setActiveEscrows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);

  // ═══════════════════════════════════════════
  // 5. VERİ ÇEKME: API ÇAĞRILARI VE POLLİNG
  //    All data fetching effects and callbacks
  // ═══════════════════════════════════════════

  // [TR] Protokol yapılandırması (bond oranları) — uygulama başlangıcında bir kez çekilir
  // [EN] Protocol config (bond rates) — fetched once on app start
  useEffect(() => {
    fetch(`${API_URL}/api/listings/config`, { credentials: 'include' })
      .then(r => r.json())
      .then(data => {
        if (data.bondMap) setOnchainBondMap(data.bondMap);
      })
      .catch(err => console.error('[ProtocolConfig] fetch failed:', err));
  }, []);

  // [TR] CHALLENGED aşamasında bleeding escrow decay miktarlarını her 30 sn'de günceller
  // [EN] Updates bleeding escrow decay amounts every 30s during CHALLENGED phase
  useEffect(() => {
    if (tradeState !== 'CHALLENGED' || !activeTrade?.onchainId || !getCurrentAmounts) {
      setBleedingAmounts(null);
      return;
    }
    const fetchAmounts = async () => {
      const result = await getCurrentAmounts(activeTrade.onchainId);
      if (result) setBleedingAmounts(result);
    };
    fetchAmounts();
    const interval = setInterval(fetchAmounts, 30000);
    return () => clearInterval(interval);
  }, [tradeState, activeTrade?.onchainId, getCurrentAmounts]);

  // [TR] HTTP-Only Cookie tabanlı kimlik doğrulamalı fetch wrapper.
  //      401 alırsa refresh token ile yeniler, başarısızsa oturumu sona erdirir.
  // [EN] Cookie-based authenticated fetch wrapper.
  //      On 401, attempts token refresh; on failure, ends the session.
  const authenticatedFetch = React.useCallback(async (url, options = {}) => {
    const res = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Content-Type': 'application/json',
      },
      credentials: 'include',
    });

    if (res.status !== 401) return res;

    try {
      const refreshRes = await fetch(`${API_URL}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ wallet: address?.toLowerCase() }),
      });

      if (!refreshRes.ok) {
        console.warn('[Auth] Refresh token expired — re-login required');
        setIsAuthenticated(false);
        showToast(lang === 'TR' ? 'Oturumunuz sona erdi. Lütfen tekrar imzalayın.' : 'Session expired. Please sign in again.', 'error');
        return res;
      }

      return fetch(url, {
        ...options,
        headers: { ...options.headers, 'Content-Type': 'application/json' },
        credentials: 'include',
      });
    } catch (err) {
      console.error('[Auth] Refresh failed:', err);
      return res;
    }
  }, [address, lang]);

  // [TR] Sayfa yüklendiğinde mevcut oturumu kontrol eder
  // [EN] Checks existing session on page load
  useEffect(() => {
    if (!isConnected || !address) {
      setIsAuthenticated(false);
      setAuthChecked(true);
      return;
    }
    fetch(`${API_URL}/api/auth/me`, { credentials: 'include' })
      .then(res => {
        setIsAuthenticated(res.ok);
        setAuthChecked(true);
      })
      .catch(() => {
        setIsAuthenticated(false);
        setAuthChecked(true);
      });
  }, [isConnected, address]);

  // [TR] Pazar yeri ilanlarını çeker — herkese açık endpoint
  // [EN] Fetches marketplace listings — public endpoint
  useEffect(() => {
    const fetchListings = async () => {
      try {
        setLoading(true);
        const res = await fetch(`${API_URL}/api/listings`, { credentials: 'include' });
        const data = await res.json();
        if (data.listings) {
          setOrders(data.listings.map(l => ({
            id:          l._id,
            onchainId:   l.onchain_escrow_id || null,
            makerFull:   l.maker_address,
            maker:       formatAddress(l.maker_address),
            crypto:      l.crypto_asset || 'USDT',
            fiat:        l.fiat_currency || 'TRY',
            rate:        l.exchange_rate,
            min:         l.limits?.min || 0,
            max:         l.limits?.max || 0,
            tier:        l.tier_rules?.required_tier ?? 1,
            bond:        (l.tier_rules?.maker_bond_pct ?? 0) + '%',
            successRate: 100,
            txCount:     0,
          })));
        }
      } catch (err) {
        console.error('Listing fetch error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchListings();
  }, [lang]);

  // [TR] Protokol istatistiklerini çeker — retry butonu için useCallback ile sarıldı
  // [EN] Fetches protocol stats — wrapped in useCallback for retry button access
  const fetchStats = React.useCallback(async () => {
    try {
      setStatsError(false);
      setStatsLoading(true);
      const res  = await fetch(`${API_URL}/api/stats`, { credentials: 'include' });
      const data = await res.json();
      if (data.stats) setProtocolStats(data.stats);
      else setStatsError(true);
    } catch (err) {
      console.error('Stats fetch error:', err);
      setStatsError(true);
    } finally {
      setStatsLoading(false);
    }
  }, []);

  useEffect(() => { fetchStats(); }, [fetchStats]);

  // [TR] Cüzdan bağlandığında on-chain kayıt durumunu kontrol eder
  // [EN] Checks on-chain wallet registration status when wallet connects
  useEffect(() => {
    if (!isConnected || !address || !publicClient) {
      setIsWalletRegistered(null);
      return;
    }
    const ESCROW_ADDR = import.meta.env.VITE_ESCROW_ADDRESS;
    if (!ESCROW_ADDR || ESCROW_ADDR === '0x0000000000000000000000000000000000000000') {
      setIsWalletRegistered(null);
      return;
    }
    const checkRegistration = async () => {
      try {
        const { getAddress, parseAbi: _parseAbi } = await import('viem');
        const regAbi = _parseAbi(['function walletRegisteredAt(address) view returns (uint256)']);
        const regAt = await publicClient.readContract({
          address: getAddress(ESCROW_ADDR),
          abi: regAbi,
          functionName: 'walletRegisteredAt',
          args: [getAddress(address)],
        });
        setIsWalletRegistered(regAt > 0n);
      } catch {
        setIsWalletRegistered(null);
      }
    };
    checkRegistration();
  }, [isConnected, address, publicClient]);

  // [TR] Kullanıcının on-chain itibar verisini ve efektif tier'ını çeker
  // [EN] Fetches user's on-chain reputation data and effective tier
  useEffect(() => {
    if (!isConnected || !address || !getReputation) {
      setUserReputation(null);
      return;
    }
    const fetchUserReputation = async () => {
      try {
        const repData = await getReputation(address);
        const successful     = typeof repData.successful     !== 'undefined' ? repData.successful     : repData[0];
        const failed         = typeof repData.failed         !== 'undefined' ? repData.failed         : repData[1];
        const bannedUntil    = typeof repData.bannedUntil    !== 'undefined' ? repData.bannedUntil    : repData[2];
        const consecutiveBans= typeof repData.consecutiveBans!== 'undefined' ? repData.consecutiveBans: repData[3];
        const effectiveTier  = typeof repData.effectiveTier  !== 'undefined' ? repData.effectiveTier  : repData[4];
        const firstTradeAt   = getFirstSuccessfulTradeAt ? await getFirstSuccessfulTradeAt(address) : 0n;

        setUserReputation({
          successful: Number(successful),
          failed: Number(failed),
          bannedUntil: Number(bannedUntil),
          consecutiveBans: Number(consecutiveBans),
          effectiveTier: Number(effectiveTier),
          firstSuccessfulTradeAt: Number(firstTradeAt),
        });
        setIsBanned(Number(bannedUntil) > Date.now() / 1000);
      } catch (err) {
        console.error('Kullanıcı itibar verisi çekilemedi:', err);
      }
    };
    fetchUserReputation();
  }, [isConnected, address, getReputation, getFirstSuccessfulTradeAt]);

  // [TR] Anti-Sybil cooldown ve bakiye durumunu her 30 sn'de kontrol eder
  // [EN] Checks anti-sybil cooldown and balance status every 30s
  useEffect(() => {
    if (!isConnected || !address || !antiSybilCheck) return;
    const fetchSybil = async () => {
      const res = await antiSybilCheck(address);
      if (res) {
        setSybilStatus({
          funded:            typeof res.balanceOk   !== 'undefined' ? res.balanceOk   : (typeof res.funded       !== 'undefined' ? res.funded       : res[1]),
          cooldownOk:        typeof res.cooldownOk  !== 'undefined' ? res.cooldownOk  : res[2],
          cooldownRemaining: 0,
        });
      }
    };
    fetchSybil();
    const interval = setInterval(fetchSybil, 30000);
    return () => clearInterval(interval);
  }, [isConnected, address, antiSybilCheck]);

  // [TR] Kontratın bakım/paused durumunu her 60 sn'de kontrol eder
  // [EN] Checks contract paused/maintenance status every 60s
  useEffect(() => {
    if (!getPaused) return;
    const fetchPausedStatus = async () => {
      try {
        const paused = await getPaused();
        setIsPaused(paused);
      } catch (err) {
        console.error('Paused durumu çekilemedi:', err);
      }
    };
    fetchPausedStatus();
    const interval = setInterval(fetchPausedStatus, 60000);
    return () => clearInterval(interval);
  }, [getPaused]);

  // [TR] Üçgen dolandırıcılık önlemi: trade odasında maker için taker'ın banka sahibi adını çeker
  // [EN] Triangulation fraud prevention: fetches taker's bank owner name for maker in trade room
  useEffect(() => {
    if (currentView === 'tradeRoom' && tradeState === 'LOCKED' && userRole === 'maker' && activeTrade?.id && isAuthenticated) {
      authenticatedFetch(`${API_URL}/api/pii/taker-name/${activeTrade.onchainId}`)
        .then(res => res.json())
        .then(data => { if (data.bankOwner) setTakerName(data.bankOwner); })
        .catch(err => console.error('Taker name fetch error', err));
    }
  }, [currentView, tradeState, userRole, activeTrade?.onchainId, isAuthenticated, authenticatedFetch]);

  // [TR] Kullanıcının aktif işlemlerini çeker. İlk yüklemede ve polling'de kullanılır.
  //      activeTrade'i her döngüde güncelleyerek zamanlayıcı tutarlılığını sağlar.
  // [EN] Fetches user's active trades. Used on initial load and polling.
  //      Updates activeTrade each cycle to keep timers consistent.
  const fetchMyTrades = React.useCallback(async () => {
    if (!isAuthenticated || !isConnected) {
      setActiveEscrows([]);
      return;
    }
    try {
      const res = await authenticatedFetch(`${API_URL}/api/trades/my`);
      const data = await res.json();
      if (data.trades) {
        setActiveEscrows(data.trades.map(t => {
          const cryptoAmt = t.financials?.crypto_amount || 0;
          const rate = t.financials?.exchange_rate || 1;
          const fiatAmt = cryptoAmt * rate;
          return {
            id: `#${t.onchain_escrow_id}`,
            role: t.maker_address.toLowerCase() === address?.toLowerCase() ? 'maker' : 'taker',
            counterparty: formatAddress(
              t.maker_address.toLowerCase() === address?.toLowerCase()
                ? (t.taker_address || '')
                : t.maker_address
            ),
            state: t.status,
            paidAt: t.timers?.paid_at,
            lockedAt: t.timers?.locked_at,
            pingedAt: t.timers?.pinged_at,
            challengePingedAt: t.timers?.challenge_pinged_at,
            challengedAt: t.timers?.challenged_at,
            onchainId: t.onchain_escrow_id,
            amount: `${cryptoAmt} ${t.financials?.crypto_asset || 'USDT'}`,
            action: t.status === 'PAID'
              ? (lang === 'TR' ? 'Onay Bekliyor' : 'Pending Approval')
              : (lang === 'TR' ? 'İşlemde' : 'In Progress'),
            rawTrade: {
              id: t._id,
              onchainId: t.onchain_escrow_id,
              maker: formatAddress(t.maker_address),
              makerFull: t.maker_address,
              takerFull: t.taker_address,
              crypto: t.financials?.crypto_asset || 'USDT',
              fiat: t.financials?.fiat_currency || 'TRY',
              rate,
              max: fiatAmt,
              paidAt: t.timers?.paid_at,
              lockedAt: t.timers?.locked_at,
              pingedAt: t.timers?.pinged_at,
              challengePingedAt: t.timers?.challenge_pinged_at,
              challengedAt: t.timers?.challenged_at,
              cancelProposedBy: t.cancel_proposal?.proposed_by,
            }
          };
        }));

        // [TR] activeTrade'i polling'de güncelleyerek paidAt/challengedAt gibi zamanlayıcı
        //      alanlarının canlı kalmasını sağlar.
        // [EN] Keeps activeTrade timer fields (paidAt, challengedAt, etc.) in sync during polling.
        setActiveTrade(prev => {
          if (!prev) return prev;
          const updated = data.trades.find(t => t.onchain_escrow_id === prev.onchainId);
          if (!updated) return prev;
          return {
            ...prev,
            state:             updated.status,
            paidAt:            updated.timers?.paid_at            ?? prev.paidAt,
            lockedAt:          updated.timers?.locked_at          ?? prev.lockedAt,
            pingedAt:          updated.timers?.pinged_at          ?? prev.pingedAt,
            challengePingedAt: updated.timers?.challenge_pinged_at ?? prev.challengePingedAt,
            challengedAt:      updated.timers?.challenged_at      ?? prev.challengedAt,
            cancelProposedBy:  updated.cancel_proposal?.proposed_by ?? prev.cancelProposedBy,
          };
        });
      }
    } catch (err) {
      console.error('Trades fetch error:', err);
    }
  }, [isAuthenticated, isConnected, address, lang, authenticatedFetch]);

  // [TR] cancelStatus'u activeEscrows'dan reaktif olarak hesaplar
  // [EN] Reactively derives cancelStatus from activeEscrows
  useEffect(() => {
    if (!activeTrade?.onchainId || !activeEscrows.length) return;
    const currentTrade = activeEscrows.find(e => e.onchainId === activeTrade.onchainId);
    if (currentTrade?.rawTrade?.cancelProposedBy) {
      const isMyProposal = currentTrade.rawTrade.cancelProposedBy.toLowerCase() === address?.toLowerCase();
      setCancelStatus(isMyProposal ? 'proposed_by_me' : 'proposed_by_other');
    } else {
      setCancelStatus(prev => prev ? null : prev);
    }
  }, [activeTrade?.onchainId, activeEscrows, address]);

  useEffect(() => { fetchMyTrades(); }, [fetchMyTrades]);

  // [TR] Trade room açıkken aktif işlemleri 15 sn'de bir yeniler
  // [EN] Refreshes active trades every 15s while trade room is open
  useEffect(() => {
    if (currentView !== 'tradeRoom' || !isAuthenticated) return;
    const interval = setInterval(fetchMyTrades, 15000);
    return () => clearInterval(interval);
  }, [currentView, isAuthenticated, fetchMyTrades]);

  // [TR] Profil modalı açıldığında mevcut PII verilerini çekip formu doldurur
  // [EN] Pre-fills PII form when profile modal opens
  useEffect(() => {
    if (!showProfileModal || !isAuthenticated) return;
    const fetchMyPII = async () => {
      try {
        const res = await authenticatedFetch(`${API_URL}/api/pii/my`);
        if (!res.ok) return;
        const data = await res.json();
        if (data.pii) {
          setPiiBankOwner(data.pii.bankOwner || '');
          setPiiIban(data.pii.iban || '');
          setPiiTelegram(data.pii.telegram || '');
        }
      } catch (err) {
        console.error('Mevcut PII verisi çekilemedi:', err);
      }
    };
    if (profileTab === 'ayarlar') fetchMyPII();
  }, [showProfileModal, profileTab, isAuthenticated, authenticatedFetch]);

  // [TR] Geçmiş sekmesi açıkken işlem geçmişini çeker ve sayfalandırır
  // [EN] Fetches and paginates trade history when history tab is active
  useEffect(() => {
    if (profileTab !== 'gecmis' || !isAuthenticated) return;
    const fetchHistory = async (page) => {
      try {
        setHistoryLoading(true);
        const res = await authenticatedFetch(`${API_URL}/api/trades/history?page=${page}&limit=5`);
        if (!res.ok) throw new Error('History fetch failed');
        const data = await res.json();
        if (data.trades) {
          setTradeHistory(data.trades);
          setTradeHistoryTotal(data.total);
          setTradeHistoryPage(data.page);
          setTradeHistoryLimit(data.limit);
        }
      } catch (err) {
        console.error('İşlem geçmişi çekilemedi:', err);
        setTradeHistory([]);
        setTradeHistoryTotal(0);
      } finally {
        setHistoryLoading(false);
      }
    };
    fetchHistory(tradeHistoryPage);
  }, [showProfileModal, profileTab, isAuthenticated, tradeHistoryPage, authenticatedFetch]);

  // [TR] Cüzdan bağlantısı kesildiğinde oturumu sona erdirir
  // [EN] Ends session when wallet disconnects
  useEffect(() => {
    if (!isConnected) setIsAuthenticated(false);
  }, [isConnected, address]);

  // ═══════════════════════════════════════════
  // 6. TÜRETILMIŞ STATE (COMPUTED VALUES)
  //    Filtered lists, countdown timers, counts
  // ═══════════════════════════════════════════

  const filteredOrders = orders.filter(order => {
    const amountMatch = searchAmount === '' || (Number(searchAmount) >= order.min && Number(searchAmount) <= order.max);
    const tierMatch   = filterTier1 ? order.tier === 0 : true;
    const tokenMatch  = filterToken === 'ALL' || order.crypto === filterToken;
    return amountMatch && tierMatch && tokenMatch;
  });

  const activeEscrowCounts = {
    LOCKED:    activeEscrows.filter(e => e.state === 'LOCKED').length,
    PAID:      activeEscrows.filter(e => e.state === 'PAID').length,
    CHALLENGED:activeEscrows.filter(e => e.state === 'CHALLENGED').length,
  };

  // [TR] Geri sayım hook'ları — React kuralı gereği component gövdesinde tanımlanır,
  //      renderTradeRoom gibi render fonksiyonlarının içinde çağrılamaz.
  // [EN] Countdown hooks — must be at component body level per React rules;
  //      cannot be called inside render helper functions like renderTradeRoom.
  const gracePeriodEndDate          = activeTrade?.paidAt ? new Date(new Date(activeTrade.paidAt).getTime() + 48 * 3600 * 1000) : null;
  const gracePeriodTimer            = useCountdown(gracePeriodEndDate);
  const challengeCountdown          = useCountdown(activeTrade?.challengePingedAt ? new Date(new Date(activeTrade.challengePingedAt).getTime() + 24 * 3600 * 1000) : null);
  const canChallenge                = import.meta.env.DEV ? (cooldownPassed || challengeCountdown.isFinished) : challengeCountdown.isFinished;
  const bleedingEndDate             = activeTrade?.challengedAt ? new Date(new Date(activeTrade.challengedAt).getTime() + 240 * 3600 * 1000) : null;
  const bleedingTimer               = useCountdown(bleedingEndDate);
  const principalProtectionEndDate  = activeTrade?.challengedAt ? new Date(new Date(activeTrade.challengedAt).getTime() + (48 + 96) * 3600 * 1000) : null;
  const principalProtectionTimer    = useCountdown(principalProtectionEndDate);
  const makerPingEndDate            = activeTrade?.paidAt ? new Date(new Date(activeTrade.paidAt).getTime() + 48 * 3600 * 1000) : null;
  const makerPingTimer              = useCountdown(makerPingEndDate);
  const canMakerPing                = makerPingTimer.isFinished;
  const makerChallengeEndDate       = activeTrade?.challengePingedAt ? new Date(new Date(activeTrade.challengePingedAt).getTime() + 24 * 3600 * 1000) : null;
  const makerChallengeTimer         = useCountdown(makerChallengeEndDate);
  const canMakerChallenge           = makerChallengeTimer.isFinished;

  // ═══════════════════════════════════════════
  // 7. YARDIMCI FONKSİYONLAR
  //    Utility helpers
  // ═══════════════════════════════════════════

  // [TR] Toast bildirimi gösterir — 4 sn sonra otomatik kapanır
  // [EN] Shows toast notification — auto-closes after 4s
  const showToast = (message, type = 'success') => {
    setToast({ id: Date.now(), message, type });
    setTimeout(() => setToast(null), 4000);
  };

  // [TR] Sidebar'ı açar ve 5 sn sonra otomatik kapatır; hover timer'ı sıfırlar
  // [EN] Opens sidebar, auto-closes after 5s; hover resets the timer
  const openSidebar = () => {
    setSidebarOpen(true);
    if (sidebarTimerRef.current) clearTimeout(sidebarTimerRef.current);
    sidebarTimerRef.current = setTimeout(() => setSidebarOpen(false), 5000);
  };

  // [TR] Cüzdan adresini kısaltır (0x1234...5678 formatı)
  // [EN] Shortens wallet address to 0x1234...5678 format
  const formatAddress = (addr) => addr ? `${addr.slice(0, 6)}...${addr.slice(-4)}` : '—';

  const getWalletIcon = (name) => {
    const n = name.toLowerCase();
    if (n.includes('metamask')) return '🦊';
    if (n.includes('okx')) return '🖤';
    if (n.includes('coinbase')) return '🔵';
    return '👛';
  };

  // ═══════════════════════════════════════════
  // 8. KİMLİK DOĞRULAMA FONKSİYONLARI
  //    SIWE login flow
  // ═══════════════════════════════════════════

  // [TR] EIP-4361 SIWE akışı: backend'den nonce alır, mesajı imzalar, doğrular.
  //      Domain ve nonce backend'den gelir — frontend'de hardcode edilmez.
  // [EN] EIP-4361 SIWE flow: fetches nonce from backend, signs message, verifies.
  //      Domain and nonce come from backend — never hardcoded on frontend.
  const loginWithSIWE = async () => {
    if (!address) return;
    try {
      setIsLoggingIn(true);
      showToast(lang === 'TR' ? 'Lütfen cüzdanınızdan imza isteğini onaylayın 🦊' : 'Please approve the signature request in your wallet 🦊', 'info');

      const nonceRes = await fetch(`${API_URL}/api/auth/nonce?wallet=${address}`, { credentials: 'include' });
      const { nonce, siweDomain } = await nonceRes.json();

      const siweMessage = new SiweMessage({
        domain:    siweDomain,
        address,
        statement: 'Sign in to Araf Protocol to manage your trades and secure PII data.',
        uri:       window.location.origin,
        version:   '1',
        chainId,
        nonce,
        issuedAt:  new Date().toISOString(),
      });
      const message = siweMessage.prepareMessage();
      const signature = await signMessageAsync({ message });

      const verifyRes = await fetch(`${API_URL}/api/auth/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ message, signature }),
      });

      if (verifyRes.ok) {
        setIsAuthenticated(true);
        showToast(lang === 'TR' ? 'Sisteme başarıyla giriş yapıldı! 🚀' : 'Successfully signed in! 🚀', 'success');
      } else {
        const data = await verifyRes.json().catch(() => ({}));
        throw new Error(data.error || 'Doğrulama başarısız');
      }
    } catch (error) {
      console.error('SIWE Error:', error);
      if (error.message?.includes('rejected') || error.message?.includes('User rejected')) {
        showToast(lang === 'TR' ? 'İmza işlemi sizin tarafınızdan iptal edildi.' : 'Signature request was cancelled by you.', 'error');
      } else {
        showToast(lang === 'TR' ? 'Giriş başarısız oldu.' : 'Login failed.', 'error');
      }
    } finally {
      setIsLoggingIn(false);
    }
  };

  // ═══════════════════════════════════════════
  // 9. KONTRAT İŞLEM FONKSİYONLARI
  //    All on-chain transaction handlers
  // ═══════════════════════════════════════════

  // [TR] Test faucet'ı — SUPPORTED_TOKEN_ADDRESSES üzerinden token adresi alır
  //      (C-01: Variable shadowing ve yanlış env key düzeltildi)
  // [EN] Test faucet — resolves token address via SUPPORTED_TOKEN_ADDRESSES
  //      (C-01: Fixed variable shadowing and wrong env key)
  const handleMint = async (tokenName) => {
    if (!isConnected) {
      showToast(lang === 'TR' ? 'Önce cüzdanınızı bağlayın.' : 'Please connect your wallet first.', 'error');
      return;
    }
    try {
      setIsContractLoading(true);
      setLoadingText(lang === 'TR' ? `${tokenName} alınıyor...` : `Minting ${tokenName}...`);
      const tokenAddr = SUPPORTED_TOKEN_ADDRESSES[tokenName];
      if (!tokenAddr) throw new Error(lang === 'TR' ? `Test ${tokenName} adresi tanımlı değil.` : `Test ${tokenName} address not defined.`);
      await mintToken(tokenAddr);
      showToast(lang === 'TR' ? `✅ Test ${tokenName} başarıyla alındı!` : `✅ Test ${tokenName} minted successfully!`, 'success');
    } catch (err) {
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'İşlem başarısız.' : 'Transaction failed.');
      showToast(errorMessage, 'error');
    } finally {
      setIsContractLoading(false);
      setLoadingText('');
    }
  };

  // [TR] Taker "Satın Al" akışı: approve() → lockEscrow() iki adımı.
  //      Bond miktarı onchain bondMap'ten hesaplanır. İşlem sonrası realTradeId için
  //      retry loop eklendi (event listener gecikmesi 3-5 sn olabilir).
  //      (C-03: PIIDisplay 404 hatasını önleyen retry loop eklendi)
  // [EN] Taker "Buy" flow: approve() → lockEscrow() two-step.
  //      Bond amount calculated from onchain bondMap. Retry loop added for
  //      realTradeId after lockEscrow (event listener delay can be 3-5s).
  //      (C-03: Added retry loop to prevent PIIDisplay 404 error)
  const handleStartTrade = async (order) => {
    if (!window.confirm(lang === 'TR' ? 'İşlemi onaylıyor musunuz?' : 'Do you confirm the transaction?')) return;
    if (isBanned) {
      showToast(lang === 'TR' ? '🚫 Taker kısıtlamanız aktif. Süre için on-chain kaydınızı kontrol edin.' : '🚫 Taker restriction active. Check on-chain record for duration.', 'error');
      return;
    }
    if (!order.onchainId) {
      showToast(lang === 'TR' ? 'Bu ilanın on-chain ID\'si henüz yok. Lütfen daha sonra tekrar deneyin.' : 'This listing has no on-chain ID yet. Please try again later.', 'error');
      return;
    }
    if (isContractLoading) return;

    try {
      setIsContractLoading(true);
      const tokenAddress = SUPPORTED_TOKEN_ADDRESSES[order.crypto || 'USDT'];
      if (!tokenAddress) {
        showToast(lang === 'TR' ? `${order.crypto} token adresi .env dosyasında tanımlı değil.` : `${order.crypto} token address not configured.`, 'error');
        return;
      }
      if (!onchainBondMap) {
        showToast(lang === 'TR' ? 'Protokol ayarları yükleniyor...' : 'Loading protocol config...', 'info');
        setIsContractLoading(false);
        return;
      }

      const tier = order.tier ?? 1;
      const cryptoAmtRaw = BigInt(Math.round((parseFloat(order.max) || 0) * 1e6));
      const takerBondBps = BigInt(onchainBondMap[tier]?.takerBps ?? 0);
      const takerBond = (cryptoAmtRaw * takerBondBps) / 10000n;

      if (takerBond > 0n) {
        const currentAllowance = await getAllowance(tokenAddress, address);
        if (currentAllowance < takerBond) {
          setLoadingText(lang === 'TR' ? `Adım 1/2: ${order.crypto} izni veriliyor...` : `Step 1/2: Approving ${order.crypto}...`);
          await approveToken(tokenAddress, takerBond);
        }
      }

      setLoadingText(lang === 'TR' ? 'Adım 2/2: İşlem kilitleniyor...' : 'Step 2/2: Locking trade...');
      await lockEscrow(BigInt(order.onchainId));

      // [TR] Event listener gecikmesine karşı 6 deneme / 2 sn aralıklı retry loop
      // [EN] Retry loop with 6 attempts / 2s intervals against event listener delay
      let realTradeId = null;
      for (let attempt = 0; attempt < 6; attempt++) {
        try {
          const res = await authenticatedFetch(`${API_URL}/api/trades/by-escrow/${order.onchainId}`);
          if (res.ok) {
            const data = await res.json();
            realTradeId = data.trade?._id;
            if (realTradeId) break;
          }
        } catch (_) {}
        if (attempt < 5) await new Promise(r => setTimeout(r, 2000));
      }

      setActiveTrade({ ...order, id: realTradeId || order.id, onchainId: order.onchainId });
      setTradeState('LOCKED');
      setCancelStatus(null);
      setCooldownPassed(false);
      setChargebackAccepted(false);
      setCurrentView('tradeRoom');
      showToast(lang === 'TR' ? '🔒 İşlem başarıyla kilitlendi!' : '🔒 Trade locked successfully!', 'success');
    } catch (err) {
      console.error('handleStartTrade error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'İşlem kilitlenemedi.' : 'Failed to lock trade.');
      if (errorMessage.includes('rejected') || errorMessage.includes('User rejected')) {
        showToast(lang === 'TR' ? 'İşlem iptal edildi.' : 'Transaction cancelled.', 'error');
      } else {
        showToast(errorMessage, 'error');
      }
    } finally {
      setIsContractLoading(false);
      setLoadingText('');
    }
  };

  // [TR] Maker ilanını iptal eder: önce on-chain cancelOpenEscrow(), sonra UI güncellenir
  // [EN] Cancels maker listing: on-chain cancelOpenEscrow() first, then UI update
  const handleDeleteOrder = async (order) => {
    if (!order.onchainId) {
      showToast(lang === 'TR' ? 'On-chain işlem ID bulunamadı, sadece veritabanından silinecek.' : 'On-chain ID not found, deleting from DB only.', 'info');
      setOrders(prev => prev.filter(o => o.id !== order.id));
      setConfirmDeleteId(null);
      return;
    }
    if (isContractLoading) return;
    try {
      setIsContractLoading(true);
      showToast(lang === 'TR' ? 'İlan iptal ediliyor, lütfen cüzdanınızdan onaylayın...' : 'Cancelling listing, please confirm in wallet...', 'info');
      await cancelOpenEscrow(BigInt(order.onchainId));
      setOrders(prev => prev.filter(o => o.id !== order.id));
      setConfirmDeleteId(null);
      showToast(lang === 'TR' ? 'İlan iptal edildi ve fonlar iade edildi.' : 'Listing cancelled and funds returned.', 'success');
    } catch (err) {
      console.error('cancelOpenEscrow error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'On-chain iptal başarısız oldu.' : 'On-chain cancellation failed.');
      showToast(errorMessage, 'error');
    } finally {
      setIsContractLoading(false);
    }
  };

  // [TR] Dekont dosyasını backend'e yükler, dönen SHA-256 hash'ini paymentIpfsHash state'ine kaydeder.
  //      activeTrade.onchainId zorunlu — backend hangi trade'e ait olduğunu belirler.
  //      "ipfsHash" adı tarihsel; gerçekte AES-256-GCM şifreli verinin SHA-256 hash'idir.
  // [EN] Uploads receipt to backend, saves returned SHA-256 hash to paymentIpfsHash state.
  //      activeTrade.onchainId required — backend identifies which trade it belongs to.
  //      "ipfsHash" name is historical; actually SHA-256 of AES-256-GCM encrypted data.
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (!activeTrade?.onchainId) {
      showToast(lang === 'TR' ? 'Aktif işlem bulunamadı.' : 'No active trade found.', 'error');
      return;
    }
    try {
      setIsContractLoading(true);
      const formData = new FormData();
      formData.append('receipt', file);
      // [TR] Backend'in doğru trade'i bulması için on-chain ID'yi gönder
      // [EN] Send on-chain ID so backend can identify the correct trade
      formData.append('onchainEscrowId', String(activeTrade.onchainId));
      const res = await fetch(`${API_URL}/api/receipts/upload`, {
        method: 'POST',
        body: formData,
        credentials: 'include'
      });
      const data = await res.json();
      if (res.ok && data.hash) {
        setPaymentIpfsHash(data.hash);
        showToast(lang === 'TR' ? 'Dekont şifrelendi ve yüklendi.' : 'Receipt encrypted and uploaded.', 'success');
      } else {
        throw new Error(data.error || 'Upload failed');
      }
    } catch (err) {
      console.error('Dekont yükleme hatası:', err);
      showToast(lang === 'TR' ? 'Dekont yüklenemedi.' : 'Failed to upload receipt.', 'error');
    } finally {
      setIsContractLoading(false);
    }
  };

  // [TR] Taker ödeme bildirimi: ipfsHash zorunlu, kontrata reportPayment() gönderilir
  // [EN] Taker payment report: ipfsHash required, calls reportPayment() on contract
  const handleReportPayment = async () => {
    if (!activeTrade?.onchainId) {
      showToast(lang === 'TR' ? 'On-chain işlem ID bulunamadı.' : 'On-chain trade ID not found.', 'error');
      return;
    }
    if (!paymentIpfsHash.trim()) {
      showToast(lang === 'TR' ? 'Önce bir dekont yüklemelisiniz.' : 'You must upload a receipt first.', 'error');
      return;
    }
    if (isContractLoading) return;
    try {
      setIsContractLoading(true);
      showToast(lang === 'TR' ? 'Ödeme bildirimi gönderiliyor... Cüzdanınızdan onaylayın.' : 'Reporting payment... Confirm in wallet.', 'info');
      await reportPayment(BigInt(activeTrade.onchainId), paymentIpfsHash.trim());
      setTradeState('PAID');
      setCooldownPassed(false);
      setPaymentIpfsHash('');
      showToast(lang === 'TR' ? '✅ Ödeme bildirildi! 48 saatlik grace period başladı.' : '✅ Payment reported! 48h grace period started.', 'success');
    } catch (err) {
      console.error('handleReportPayment error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'Ödeme bildirimi başarısız.' : 'Payment report failed.');
      if (errorMessage.includes('rejected') || errorMessage.includes('User rejected')) {
        showToast(lang === 'TR' ? 'İşlem iptal edildi.' : 'Transaction cancelled.', 'error');
      } else {
        showToast(errorMessage, 'error');
      }
    } finally {
      setIsContractLoading(false);
    }
  };

  // [TR] Karşılıklı iptal akışı: EIP-712 imzası oluşturulur → backend relay → kontrat.
  //      sigNonces on-chain okunarak replay koruması sağlanır.
  //      Backend erişilemezse doğrudan kontrat çağrısına fallback yapılır.
  // [EN] Mutual cancel flow: creates EIP-712 signature → backend relay → contract.
  //      sigNonces read on-chain for replay protection.
  //      Falls back to direct contract call if backend is unreachable.
  const handleProposeCancel = async () => {
    if (!activeTrade?.onchainId) {
      showToast(lang === 'TR' ? 'On-chain işlem ID bulunamadı.' : 'On-chain trade ID not found.', 'error');
      return;
    }
    if (isContractLoading) return;
    try {
      setIsContractLoading(true);
      showToast(lang === 'TR' ? 'İptal imzası oluşturuluyor...' : 'Creating cancel signature...', 'info');

      const ESCROW_ADDR = import.meta.env.VITE_ESCROW_ADDRESS;
      const { getAddress, parseAbi: _parseAbi } = await import('viem');
      const nonceAbi = _parseAbi(['function sigNonces(address) view returns (uint256)']);
      const nonce = await publicClient.readContract({
        address: getAddress(ESCROW_ADDR),
        abi: nonceAbi,
        functionName: 'sigNonces',
        args: [getAddress(address)],
      });

      const { signature, deadline } = await signCancelProposal(activeTrade.onchainId, nonce);

      try {
        const relayRes = await authenticatedFetch(`${API_URL}/api/trades/propose-cancel`, {
          method: 'POST',
          body: JSON.stringify({ tradeId: activeTrade.id, signature, deadline }),
        });
        const relayData = await relayRes.json();
        if (relayData.bothSigned) {
          showToast(lang === 'TR' ? 'Her iki taraf imzaladı. Kontrata gönderiliyor...' : 'Both signed. Sending to contract...', 'info');
          await proposeOrApproveCancel(BigInt(activeTrade.onchainId), deadline, signature);
          setCancelStatus(null);
          setTradeState('CANCELED');
          setCurrentView('home');
          showToast(lang === 'TR' ? '✅ İşlem iptal edildi.' : '✅ Trade cancelled.', 'success');
        } else {
          setCancelStatus('proposed_by_me');
          showToast(lang === 'TR' ? '✅ İptal teklifi gönderildi. Karşı tarafın onayı bekleniyor.' : '✅ Cancel proposal sent. Awaiting counterparty.', 'success');
        }
      } catch (relayErr) {
        console.warn('[Cancel] Backend relay başarısız, direkt on-chain fallback:', relayErr.message);
        showToast(lang === 'TR' ? 'Backend erişilemez. Kontrata direkt gönderiliyor...' : 'Backend unreachable. Sending directly to contract...', 'info');
        await proposeOrApproveCancel(BigInt(activeTrade.onchainId), deadline, signature);
        setCancelStatus('proposed_by_me');
        showToast(lang === 'TR' ? '✅ İptal teklifi kontrata gönderildi (direkt).' : '✅ Cancel proposal sent directly to contract.', 'success');
      }
    } catch (err) {
      console.error('handleProposeCancel error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'İptal teklifi başarısız.' : 'Cancel proposal failed.');
      if (errorMessage.includes('rejected') || errorMessage.includes('User rejected')) {
        showToast(lang === 'TR' ? 'İşlem iptal edildi.' : 'Transaction cancelled.', 'error');
      } else {
        showToast(errorMessage, 'error');
      }
    } finally {
      setIsContractLoading(false);
    }
  };

  // [TR] Geri bildirim gönderimi — JWT zorunlu, form sıfırlanır
  // [EN] Feedback submission — JWT required, form resets on success
  const submitFeedback = async () => {
    if (!isAuthenticated) {
      showToast(lang === 'TR' ? 'Geri bildirim göndermek için giriş yapmalısınız.' : 'Please sign in to send feedback.', 'error');
      return;
    }
    try {
      await authenticatedFetch(`${API_URL}/api/feedback`, {
        method: 'POST',
        body: JSON.stringify({ rating: feedbackRating, comment: feedbackText, category: feedbackCategory }),
      });
    } catch (err) {
      console.error('Feedback submit error:', err);
    } finally {
      setShowFeedbackModal(false);
      setFeedbackText('');
      setFeedbackRating(0);
      setFeedbackCategory('');
      showToast(lang === 'TR' ? 'Geri bildiriminiz için teşekkürler!' : 'Thank you for your feedback!', 'success');
    }
  };

  const handleChargebackAck = (checked) => { setChargebackAccepted(checked); };

  // [TR] Maker USDT'yi serbest bırakır (releaseFunds). PAID state'te chargeback onayı zorunlu.
  //      CHALLENGED state'te bu kontrol atlanır — sessiz başarısızlığı önler.
  //      (C-02: CHALLENGED state'te chargebackAccepted guard atlatılıyor)
  // [EN] Maker releases USDT (releaseFunds). Chargeback ack required in PAID state.
  //      Skipped in CHALLENGED state — prevents silent failure.
  //      (C-02: chargebackAccepted guard bypassed in CHALLENGED state)
  const handleRelease = async () => {
    if (tradeState === 'PAID' && !chargebackAccepted) {
      showToast(lang === 'TR' ? 'Lütfen ters ibraz riskini kabul edin.' : 'Please acknowledge the chargeback risk.', 'error');
      return;
    }
    if (!activeTrade?.onchainId) {
      showToast(lang === 'TR' ? 'On-chain işlem ID bulunamadı.' : 'On-chain trade ID not found.', 'error');
      return;
    }
    if (isContractLoading) return;
    try {
      setIsContractLoading(true);
      try {
        await authenticatedFetch(`${API_URL}/api/trades/${activeTrade.id}/chargeback-ack`, { method: 'POST' });
      } catch (err) {
        console.error('Backend chargeback-ack log hatası:', err);
      }
      showToast(lang === 'TR' ? 'İşlem cüzdanınıza gönderildi, onaylayın...' : 'Transaction sent to wallet, please confirm...', 'info');
      await releaseFunds(BigInt(activeTrade.onchainId));
      setTradeState('RESOLVED');
      setCurrentView('home');
      showToast(lang === 'TR' ? 'USDT başarıyla serbest bırakıldı! ✅' : 'USDT successfully released! ✅', 'success');
    } catch (err) {
      console.error('releaseFunds error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'Kontrat işlemi başarısız oldu.' : 'Contract transaction failed.');
      if (errorMessage.includes('rejected') || errorMessage.includes('User rejected')) {
        showToast(lang === 'TR' ? 'İşlem sizin tarafınızdan iptal edildi.' : 'Transaction cancelled by you.', 'error');
      } else {
        showToast(errorMessage, 'error');
      }
    } finally {
      setIsContractLoading(false);
    }
  };

  // [TR] İtiraz akışı iki adımlı: önce taker'a ping (pingTakerForChallenge), 24 saat
  //      sonra challengeTrade çağrısı yapılabilir. Her iki adım sonrası fetchMyTrades çağrılır.
  //      (H-04: fetchMyTrades eklendi — 15 sn polling beklenmeden UI güncellenir)
  // [EN] Two-step challenge flow: ping taker first (pingTakerForChallenge), then
  //      challengeTrade after 24h. fetchMyTrades called after both steps.
  //      (H-04: Added fetchMyTrades — UI updates without waiting for 15s polling)
  const handleChallenge = async () => {
    if (!activeTrade?.onchainId) return;
    if (isContractLoading) return;

    const tradeDetails = activeEscrows.find(e => e.id === `#${activeTrade.onchainId}`);
    const challengePingedAt = tradeDetails?.challengePingedAt;

    if (!challengePingedAt) {
      try {
        setIsContractLoading(true);
        showToast(lang === 'TR' ? 'Alıcıya uyarı gönderiliyor...' : 'Pinging taker...', 'info');
        await pingTakerForChallenge(BigInt(activeTrade.onchainId));
        setActiveTrade(prev => ({ ...prev, challengePingedAt: new Date().toISOString() }));
        await fetchMyTrades();
        showToast(lang === 'TR' ? 'Alıcı uyarıldı. İtiraz için 24 saat beklemeniz gerekiyor.' : 'Taker pinged. You must wait 24h to challenge.', 'success');
      } catch (err) {
        console.error('pingTakerForChallenge error:', err);
        const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'Uyarı gönderilemedi.' : 'Failed to send ping.');
        showToast(errorMessage, 'error');
      } finally {
        setIsContractLoading(false);
      }
      return;
    }

    try {
      setIsContractLoading(true);
      showToast(lang === 'TR' ? 'İtiraz işlemi cüzdanınıza gönderildi...' : 'Challenge transaction sent to wallet...', 'info');
      await challengeTrade(BigInt(activeTrade.onchainId));
      setTradeState('CHALLENGED');
      setActiveTrade(prev => ({ ...prev, challengedAt: new Date().toISOString() }));
      await fetchMyTrades();
      showToast(lang === 'TR' ? 'İtiraz başlatıldı. Bleeding Escrow aktif.' : 'Challenge opened. Bleeding Escrow active.', 'success');
    } catch (err) {
      console.error('challengeTrade error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'İtiraz işlemi başarısız.' : 'Challenge failed.');
      showToast(errorMessage, 'error');
    } finally {
      setIsContractLoading(false);
    }
  };

  // [TR] Maker'a 48 saat sonra uyarı gönderir — taker tarafından çağrılır
  // [EN] Sends ping to maker after 48h — called by taker
  const handlePingMaker = async (tradeId) => {
    if (!tradeId || isContractLoading) return;
    try {
      setIsContractLoading(true);
      showToast(lang === 'TR' ? 'Uyarı işlemi cüzdanınıza gönderiliyor...' : 'Pinging maker, please confirm in wallet...', 'info');
      await pingMaker(BigInt(tradeId));
      setActiveTrade(prev => ({ ...prev, pingedAt: new Date().toISOString() }));
      showToast(lang === 'TR' ? 'Satıcı uyarıldı. Yanıt için 24 saati var.' : 'Maker has been pinged. They have 24h to respond.', 'success');
    } catch (err) {
      console.error('pingMaker error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'Ping işlemi başarısız oldu.' : 'Ping failed.');
      if (errorMessage.includes('rejected') || errorMessage.includes('User rejected')) {
        showToast(lang === 'TR' ? 'İşlem iptal edildi.' : 'Transaction cancelled.', 'error');
      } else {
        showToast(errorMessage, 'error');
      }
    } finally {
      setIsContractLoading(false);
    }
  };

  // [TR] Maker pasif kalırsa taker 24 saat sonra autoRelease çağırabilir (%2 ihmal cezası kesilir)
  // [EN] If maker is passive, taker can call autoRelease after 24h (2% negligence penalty deducted)
  const handleAutoRelease = async (tradeId) => {
    if (!tradeId || isContractLoading) return;
    try {
      setIsContractLoading(true);
      showToast(lang === 'TR' ? 'Otomatik serbest bırakma işlemi cüzdanınıza gönderiliyor...' : 'Auto-release transaction sent to wallet...', 'info');
      await autoRelease(BigInt(tradeId));
      setTradeState('RESOLVED');
      setCurrentView('home');
      showToast(lang === 'TR' ? 'İşlem başarıyla sonlandırıldı. Fonlar cüzdanınıza aktarıldı.' : 'Trade successfully resolved. Funds transferred to your wallet.', 'success');
    } catch (err) {
      console.error('autoRelease error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'Otomatik serbest bırakma başarısız oldu.' : 'Auto-release failed.');
      if (errorMessage.includes('rejected') || errorMessage.includes('User rejected')) {
        showToast(lang === 'TR' ? 'İşlem iptal edildi.' : 'Transaction cancelled.', 'error');
      } else {
        showToast(errorMessage, 'error');
      }
    } finally {
      setIsContractLoading(false);
    }
  };

  // [TR] Kullanıcının banka/IBAN/Telegram bilgilerini günceller (AES-256 şifreli, off-chain)
  // [EN] Updates user's bank/IBAN/Telegram info (AES-256 encrypted, off-chain)
  const handleUpdatePII = async (e) => {
    e.preventDefault();
    if (!isAuthenticated || isContractLoading) return;
    try {
      setIsContractLoading(true);
      const res = await authenticatedFetch(`${API_URL}/api/auth/profile`, {
        method: 'PUT',
        body: JSON.stringify({
          bankOwner: piiBankOwner,
          iban:      piiIban.replace(/\s/g, ''),
          telegram:  piiTelegram.replace(/^@/, '').trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Güncelleme başarısız oldu.');
      showToast(lang === 'TR' ? 'Bilgileriniz başarıyla güncellendi.' : 'Your information has been updated successfully.', 'success');
    } catch (err) {
      console.error('PII update error:', err);
      showToast(err.message, 'error');
    } finally {
      setIsContractLoading(false);
    }
  };

  // [TR] Telegram handle'ından güvenli URL oluşturur — özel karakter injection'ını önler
  // [EN] Builds safe Telegram URL from handle — prevents special character injection
  const getSafeTelegramUrl = React.useCallback((handle) => {
    if (!handle) return '#';
    const safeHandle = handle.replace(/[^a-zA-Z0-9_]/g, '');
    return `https://t.me/${safeHandle}`;
  }, []);

  // [TR] Yeni cüzdanı on-chain'e kaydeder — taker olabilmek için 7 günlük bekleme başlar
  // [EN] Registers new wallet on-chain — starts 7-day waiting period for taker eligibility
  const handleRegisterWallet = async () => {
    if (isRegisteringWallet || isWalletRegistered) return;
    try {
      setIsRegisteringWallet(true);
      showToast(lang === 'TR' ? 'Cüzdan kaydediliyor... Cüzdanınızdan onaylayın.' : 'Registering wallet... Confirm in wallet.', 'info');
      await registerWallet();
      setIsWalletRegistered(true);
      showToast(
        lang === 'TR'
          ? '✅ Cüzdan kaydedildi! 7 gün sonra Taker olarak işlem başlatabilirsiniz.'
          : '✅ Wallet registered! You can start as Taker after 7 days.',
        'success'
      );
    } catch (err) {
      console.error('handleRegisterWallet error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'Kayıt başarısız.' : 'Registration failed.');
      if (errorMessage.includes('AlreadyRegistered')) {
        setIsWalletRegistered(true);
        showToast(lang === 'TR' ? 'Cüzdan zaten kayıtlı.' : 'Wallet already registered.', 'info');
      } else if (errorMessage.includes('rejected') || errorMessage.includes('User rejected')) {
        showToast(lang === 'TR' ? 'İşlem iptal edildi.' : 'Transaction cancelled.', 'error');
      } else {
        showToast(errorMessage, 'error');
      }
    } finally {
      setIsRegisteringWallet(false);
    }
  };

  const handleOpenMakerModal = () => {
    if (isPaused) {
      showToast(lang === 'TR' ? 'Sistem şu an bakım modundadır. Yeni ilan açılamaz.' : 'System is paused. Cannot create ad.', 'error');
      return;
    }
    if (!isConnected || !isAuthenticated) {
      showToast(lang === 'TR' ? 'İlan açmak için önce cüzdanınızı bağlayıp imzalamalısınız.' : 'Please connect and sign in to create an ad.', 'error');
      return;
    }
    setShowMakerModal(true);
  };

  // [TR] Maker escrow oluşturma: allowance kontrol → approve() → createEscrow() iki adım.
  //      Bond miktarı onchain bondMap'ten dinamik hesaplanır.
  //      İlan önce off-chain DB'ye kaydedilir ki event listener eşleşebilsin.
  // [EN] Maker escrow creation: check allowance → approve() → createEscrow() two-step.
  //      Bond amount dynamically calculated from onchain bondMap.
  //      Listing pre-saved to off-chain DB so event listener can match it.
  const handleCreateEscrow = async () => {
    const tokenAddress = SUPPORTED_TOKEN_ADDRESSES[makerToken];
    if (!tokenAddress) {
      showToast(lang === 'TR' ? `${makerToken} token adresi .env dosyasında tanımlı değil (VITE_${makerToken}_ADDRESS).` : `${makerToken} token address not configured in .env (VITE_${makerToken}_ADDRESS).`, 'error');
      return;
    }
    const cryptoAmt = parseFloat(makerAmount);
    if (!cryptoAmt || cryptoAmt <= 0) {
      showToast(lang === 'TR' ? 'Geçerli bir miktar girin.' : 'Enter a valid amount.', 'error');
      return;
    }
    if (!makerRate || parseFloat(makerRate) <= 0) {
      showToast(lang === 'TR' ? 'Kur fiyatı girilmeli.' : 'Enter an exchange rate.', 'error');
      return;
    }
    if (isContractLoading) return;

    try {
      try {
        await authenticatedFetch(`${API_URL}/api/listings`, {
          method: 'POST',
          body: JSON.stringify({
            crypto_asset:  makerToken,
            fiat_currency: makerFiat,
            exchange_rate: parseFloat(makerRate),
            limits: { min: parseFloat(makerMinLimit), max: parseFloat(makerMaxLimit) },
            tier: makerTier,
            token_address: SUPPORTED_TOKEN_ADDRESSES[makerToken],
          }),
        });
      } catch (e) {
        console.warn('Off-chain ilan pre-creation uyarısı:', e);
      }

      setIsContractLoading(true);

      const decimals = BigInt(6);
      const cryptoAmountRaw = BigInt(Math.round(cryptoAmt * 10 ** Number(decimals)));

      if (!onchainBondMap) {
        showToast(lang === 'TR' ? 'Protokol ayarları yükleniyor...' : 'Loading protocol config...', 'info');
        setIsContractLoading(false);
        return;
      }
      const bondBps = BigInt(onchainBondMap[makerTier]?.makerBps ?? 0);
      const makerBondRaw = (cryptoAmountRaw * bondBps) / 10000n;
      const totalLock = cryptoAmountRaw + makerBondRaw;

      const currentAllowance = await getAllowance(tokenAddress, address);
      if (currentAllowance < totalLock) {
        setLoadingText(lang === 'TR' ? `Adım 1/2: ${makerToken} izni veriliyor...` : `Step 1/2: Approving ${makerToken}...`);
        await approveToken(tokenAddress, totalLock);
      }

      setLoadingText(lang === 'TR' ? 'Adım 2/2: Escrow oluşturuluyor...' : 'Step 2/2: Creating escrow...');
      await createEscrow(tokenAddress, cryptoAmountRaw, makerTier);

      showToast(
        lang === 'TR' ? '✅ İlan başarıyla oluşturuldu! Fonlar kilitlendi.' : '✅ Listing created! Funds locked.',
        'success'
      );
      setShowMakerModal(false);
      setMakerAmount('');
      setMakerRate('');
      setMakerMinLimit('');
      setMakerMaxLimit('');
      setMakerFiat('TRY');
    } catch (err) {
      console.error('handleCreateEscrow error:', err);
      const errorMessage = err.shortMessage || err.reason || err.message || (lang === 'TR' ? 'Escrow oluşturulamadı.' : 'Failed to create escrow.');
      if (errorMessage.includes('rejected') || errorMessage.includes('User rejected')) {
        showToast(lang === 'TR' ? 'İşlem iptal edildi.' : 'Transaction cancelled.', 'error');
      } else {
        showToast(errorMessage, 'error');
      }
    } finally {
      setIsContractLoading(false);
      setLoadingText('');
    }
  };

  // [TR] Navbar auth butonu: bağlı değilse wallet modal, imzasızsa SIWE, imzalıysa profil açar
  // [EN] Navbar auth button: opens wallet modal if not connected, SIWE if unsigned, profile if signed
  const handleAuthAction = () => {
    if (!isConnected) setShowWalletModal(true);
    else if (!isAuthenticated) loginWithSIWE();
    else { setProfileTab('ayarlar'); setShowProfileModal(true); }
  };

  // ─────────────────────────────────────────────
  // [TR] Çeviri sözlüğü — yalnızca pazar yeri ana metinleri
  // [EN] Translation dictionary — marketplace main labels only
  // ─────────────────────────────────────────────
  const t = {
    title:           lang === 'TR' ? 'Pazar Yeri' : 'Marketplace',
    subtitle:        lang === 'TR' ? 'Merkeziyetsiz, hakemsiz P2P takas tahtası.' : 'Decentralized, oracle-free P2P escrow board.',
    searchPlaceholder: lang === 'TR' ? 'Tutar Ara...' : 'Search Amount...',
    bondFilter:      lang === 'TR' ? '%0 Teminat' : '0% Bond',
    vol:             lang === 'TR' ? 'Toplam Hacim' : 'Total Volume',
    trades:          lang === 'TR' ? 'Başarılı İşlem' : 'Success Trades',
    users:           lang === 'TR' ? 'Aktif Kullanıcı' : 'Active Users',
    burn:            lang === 'TR' ? 'Eriyen Kasa' : 'Burned Treasury',
    tableSeller:     lang === 'TR' ? 'Satıcı' : 'Seller',
    tableRate:       lang === 'TR' ? 'Kur' : 'Rate',
    tableLimit:      lang === 'TR' ? 'Limit' : 'Limit',
    tableBond:       lang === 'TR' ? 'Bond' : 'Bond',
    tableAction:     lang === 'TR' ? 'İşlem' : 'Action',
    buyBtn:          lang === 'TR' ? 'Satın Al' : 'Buy',
    createAd:        lang === 'TR' ? '+ İlan Aç' : '+ Create Ad',
  };

  // ═══════════════════════════════════════════
  // 10. MODAL RENDER FONKSİYONLARI
  //     Wallet, Feedback, Maker, Profile modals
  // ═══════════════════════════════════════════

  // [TR] Cüzdan bağlama modalı — wagmi connector listesini gösterir
  // [EN] Wallet connection modal — renders wagmi connector list
  const renderWalletModal = () => {
    if (!showWalletModal) return null;
    return (
      <div className="fixed inset-0 bg-[#060608]/90 backdrop-blur-md flex items-center justify-center p-4 z-[100]">
        <div className="bg-[#111113] border border-[#222] rounded-2xl p-6 w-full max-w-sm shadow-2xl max-h-[90vh] overflow-y-auto">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-bold text-white">{lang === 'TR' ? 'Cüzdan Seçin' : 'Select Wallet'}</h2>
            <button onClick={() => setShowWalletModal(false)} className="text-slate-400 hover:text-white text-2xl leading-none">&times;</button>
          </div>
          <div className="space-y-3">
            {connectors.map((connector) => (
              <button
                key={connector.uid}
                onClick={() => { connect({ connector }); setShowWalletModal(false); }}
                className="w-full flex items-center justify-between bg-[#151518] hover:bg-[#1a1a1f] border border-[#2a2a2e] p-4 rounded-xl transition-all group"
              >
                <div className="flex items-center space-x-3">
                  <span className="text-2xl">{getWalletIcon(connector.name)}</span>
                  <span className="font-bold text-white group-hover:text-emerald-400">{connector.name}</span>
                </div>
                <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Connect</span>
              </button>
            ))}
          </div>
          <p className="mt-6 text-[10px] text-center text-slate-500 italic">
            {lang === 'TR' ? '* Araf Protocol hiçbir zaman private key istemez.' : '* Araf Protocol never asks for private keys.'}
          </p>
        </div>
      </div>
    );
  };

  // [TR] Geri bildirim modalı — kategori + yıldız puanı + metin girişi
  // [EN] Feedback modal — category + star rating + text input
  const renderFeedbackModal = () => {
    if (!showFeedbackModal) return null;
    return (
      <div className="fixed inset-0 bg-[#060608]/80 backdrop-blur-sm flex items-center justify-center p-4 z-[100]">
        <div className="bg-[#111113] border border-[#222] rounded-2xl p-6 w-full max-w-sm shadow-2xl max-h-[90vh] overflow-y-auto">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-bold text-white">{lang === 'TR' ? 'Geri Bildirim' : 'Feedback'}</h2>
            <button onClick={() => setShowFeedbackModal(false)} className="text-slate-400 hover:text-white text-2xl">&times;</button>
          </div>
          <p className="text-sm text-slate-400 mb-4">{lang === 'TR' ? 'Araf Protocol deneyiminizi nasıl buldunuz?' : 'How is your experience with Araf Protocol?'}</p>
          <div className="flex justify-center space-x-2 mb-4">
            {[1, 2, 3, 4, 5].map((star) => (
              <button key={star} onClick={() => setFeedbackRating(star)} className={`text-3xl transition ${feedbackRating >= star ? 'text-yellow-400 scale-110' : 'text-slate-600 hover:text-yellow-400/50'}`}>★</button>
            ))}
          </div>
          <select
            value={feedbackCategory}
            onChange={(e) => setFeedbackCategory(e.target.value)}
            className="w-full bg-[#151518] text-white px-3 py-2.5 rounded-xl border border-[#2a2a2e] outline-none text-sm mb-4"
          >
            <option value="" disabled>{lang === 'TR' ? 'Kategori Seçin...' : 'Select Category...'}</option>
            <option value="bug">{lang === 'TR' ? '🐞 Hata Bildirimi' : '🐞 Bug Report'}</option>
            <option value="suggestion">{lang === 'TR' ? '💡 Özellik İsteği' : '💡 Feature Suggestion'}</option>
            <option value="ui/ux">{lang === 'TR' ? '🎨 Tasarım/Kullanıcı Deneyimi' : '🎨 Design/UX'}</option>
            <option value="other">{lang === 'TR' ? 'Diğer' : 'Other'}</option>
          </select>
          <textarea value={feedbackText} onChange={(e) => setFeedbackText(e.target.value)} placeholder={lang === 'TR' ? 'Düşünceleriniz veya bulduğunuz hatalar...' : 'Your thoughts or bugs found...'} className="w-full bg-[#151518] text-white px-3 py-3 rounded-xl border border-[#2a2a2e] outline-none h-24 text-sm mb-4 resize-none"></textarea>
          <button onClick={submitFeedback} disabled={feedbackRating === 0 || feedbackCategory === ''} className={`w-full py-3 rounded-xl font-bold transition ${feedbackRating > 0 && feedbackCategory !== '' ? 'bg-emerald-600 hover:bg-emerald-500 text-white' : 'bg-slate-700 text-slate-500 cursor-not-allowed'}`}>
            {lang === 'TR' ? 'Gönder' : 'Submit'}
          </button>
        </div>
      </div>
    );
  };

  // [TR] Maker ilan oluşturma modalı — tier seçimi, form validasyonu ve bond hesabı
  // [EN] Maker listing creation modal — tier selection, form validation and bond calculation
  const renderMakerModal = () => {
    if (!showMakerModal) return null;

    const TIER_LABELS = {
      0: lang === 'TR' ? 'Tier 0 — Bond Yok (Yeni)' : 'Tier 0 — No Bond (New)',
      1: lang === 'TR' ? 'Tier 1 — %8 Bond (Başlangıç)' : 'Tier 1 — 8% Bond (Starter)',
      2: lang === 'TR' ? 'Tier 2 — %6 Bond (Standart)'  : 'Tier 2 — 6% Bond (Standard)',
      3: lang === 'TR' ? 'Tier 3 — %5 Bond (Deneyimli)' : 'Tier 3 — 5% Bond (Pro)',
      4: lang === 'TR' ? 'Tier 4 — %2 Bond (Premium)'   : 'Tier 4 — 2% Bond (Premium)',
    };

    const bondPct = onchainBondMap ? (onchainBondMap[makerTier]?.maker ?? 0) : 0;
    const cryptoAmt  = parseFloat(makerAmount) || 0;
    const bondAmt    = Math.ceil(cryptoAmt * bondPct / 100);
    const totalLock  = cryptoAmt + bondAmt;
    const effectiveUserTier = userReputation?.effectiveTier ?? 0;

    const cryptoAmtNum = parseFloat(makerAmount) || 0;
    const rateNum      = parseFloat(makerRate) || 0;
    const minLimNum    = parseFloat(makerMinLimit) || 0;
    const maxLimNum    = parseFloat(makerMaxLimit) || 0;
    const totalFiatValue = cryptoAmtNum * rateNum;

    let validationError = null;
    if (!makerAmount || cryptoAmtNum <= 0)                    validationError = lang === 'TR' ? 'Satılacak miktarı giriniz.' : 'Enter amount to sell.';
    else if (makerTier === 0 && cryptoAmtNum > 150)           validationError = lang === 'TR' ? 'Tier 0 maksimum ilan limiti 150 USDT/USDC.' : 'Tier 0 max limit is 150 USDT/USDC.';
    else if (makerTier === 1 && cryptoAmtNum > 1500)          validationError = lang === 'TR' ? 'Tier 1 maksimum ilan limiti 1.500 USDT/USDC.' : 'Tier 1 max limit is 1500 USDT/USDC.';
    else if (makerTier === 2 && cryptoAmtNum > 7500)          validationError = lang === 'TR' ? 'Tier 2 maksimum ilan limiti 7.500 USDT/USDC.' : 'Tier 2 max limit is 7500 USDT/USDC.';
    else if (makerTier === 3 && cryptoAmtNum > 30000)         validationError = lang === 'TR' ? 'Tier 3 maksimum ilan limiti 30.000 USDT/USDC.' : 'Tier 3 max limit is 30000 USDT/USDC.';
    else if (!makerRate || rateNum <= 0)                      validationError = lang === 'TR' ? 'Kur fiyatını giriniz.' : 'Enter exchange rate.';
    else if (!makerMinLimit || minLimNum <= 0)                validationError = lang === 'TR' ? 'Minimum işlem limitini giriniz.' : 'Enter min limit.';
    else if (!makerMaxLimit || maxLimNum <= 0)                validationError = lang === 'TR' ? 'Maksimum işlem limitini giriniz.' : 'Enter max limit.';
    else if (minLimNum > maxLimNum)                           validationError = lang === 'TR' ? 'Min limit, Max limitten büyük olamaz.' : 'Min limit cannot exceed Max.';
    else if (maxLimNum > totalFiatValue)                      validationError = lang === 'TR' ? `Max limit toplam değeri (${totalFiatValue.toFixed(2)} ${makerFiat}) aşamaz.` : `Max limit exceeds total fiat (${totalFiatValue.toFixed(2)} ${makerFiat}).`;

    return (
      <div className="fixed inset-0 bg-[#060608]/80 backdrop-blur-sm flex items-center justify-center p-4 z-[100]">
        <div className="bg-[#111113] border border-[#222] rounded-2xl p-6 w-full max-w-md shadow-2xl max-h-[90vh] overflow-y-auto">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-bold text-white">{t.createAd}</h2>
            <button onClick={() => setShowMakerModal(false)} className="text-slate-400 hover:text-white text-2xl">&times;</button>
          </div>
          <div className="space-y-4">
            <div className="flex space-x-2">
              <div className="w-1/2">
                <label className="block text-xs text-slate-400 mb-1">{lang === 'TR' ? 'Satılacak Kripto' : 'Crypto to Sell'}</label>
                <select value={makerToken} onChange={e => setMakerToken(e.target.value)} className="w-full bg-[#151518] text-white px-3 py-2 rounded-xl border border-[#2a2a2e] outline-none">
                  <option value="USDT">USDT</option>
                  <option value="USDC">USDC</option>
                </select>
              </div>
              <div className="w-1/2">
                <label className="block text-xs text-slate-400 mb-1">{lang === 'TR' ? 'İstenecek İtibari Para' : 'Fiat Currency'}</label>
                <select value={makerFiat} onChange={e => setMakerFiat(e.target.value)} className="w-full bg-[#151518] text-white px-3 py-2 rounded-xl border border-[#2a2a2e] outline-none">
                  <option value="TRY">TRY</option>
                  <option value="USD">USD</option>
                  <option value="EUR">EUR</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">{lang === 'TR' ? 'Satılacak Miktar' : 'Amount'}</label>
              <input type="number" placeholder="Örn: 1000" value={makerAmount} onChange={e => setMakerAmount(e.target.value)} className="w-full bg-[#151518] text-white px-3 py-2 rounded-xl border border-[#2a2a2e] outline-none" />
            </div>
            <div className="flex space-x-2">
              <div className="w-1/2">
                <label className="block text-xs text-slate-400 mb-1">{lang === 'TR' ? 'Kur (1 USDT için)' : 'Rate (per 1 USDT)'}</label>
                <input type="number" placeholder="Örn: 33.50" value={makerRate} onChange={e => setMakerRate(e.target.value)} className="w-full bg-[#151518] text-white px-3 py-2 rounded-xl border border-[#2a2a2e] outline-none" />
              </div>
              <div className="w-1/2"></div>
            </div>
            <div className="flex space-x-2">
              <div className="w-1/2">
                <label className="block text-xs text-slate-400 mb-1">{lang === 'TR' ? 'Min. Limit' : 'Min Limit'}</label>
                <input type="number" placeholder="500" value={makerMinLimit} onChange={e => setMakerMinLimit(e.target.value)} className="w-full bg-[#151518] text-white px-3 py-2 rounded-xl border border-[#2a2a2e] outline-none" />
              </div>
              <div className="w-1/2">
                <label className="block text-xs text-slate-400 mb-1">{lang === 'TR' ? 'Max. Limit' : 'Max Limit'}</label>
                <input type="number" placeholder="2500" value={makerMaxLimit} onChange={e => setMakerMaxLimit(e.target.value)} className="w-full bg-[#151518] text-white px-3 py-2 rounded-xl border border-[#2a2a2e] outline-none" />
              </div>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">{lang === 'TR' ? 'İlan Tier Seviyesi' : 'Listing Tier'}</label>
              <select value={makerTier} onChange={e => setMakerTier(Number(e.target.value))} className="w-full bg-[#151518] text-white px-3 py-2 rounded-xl border border-[#2a2a2e] outline-none">
                {[0, 1, 2, 3, 4].map(t => (
                  <option key={t} value={t} disabled={t > effectiveUserTier}>
                    {TIER_LABELS[t]} {t > effectiveUserTier ? (lang === 'TR' ? '(Yetersiz)' : '(Too Low)') : ''}
                  </option>
                ))}
              </select>
            </div>
            <div className="mt-4 p-3 bg-emerald-900/20 border border-emerald-500/30 rounded-xl">
              <p className="text-xs text-emerald-400 mb-2 font-medium">🛡️ {TIER_LABELS[makerTier]} {lang === 'TR' ? 'Kuralları' : 'Rules'}</p>
              {bondPct > 0 ? (
                <div className="flex justify-between text-xs text-slate-300 mb-1">
                  <span>{lang === 'TR' ? 'Satıcı Teminatı' : 'Maker Bond'} (%{bondPct}):</span>
                  <span>{bondAmt > 0 ? `${bondAmt} Kripto` : '—'}</span>
                </div>
              ) : (
                <p className="text-xs text-slate-400 mb-1">{lang === 'TR' ? 'Tier 0: Teminat yok' : 'Tier 0: No bond'}</p>
              )}
              <div className="flex justify-between text-sm font-bold text-white border-t border-emerald-500/30 pt-2">
                <span>{lang === 'TR' ? 'Toplam Kilitlenecek:' : 'Total Locked:'}</span>
                <span>{totalLock > 0 ? `${totalLock} Kripto` : '—'}</span>
              </div>
            </div>
            {validationError && (
              <p className="text-red-400 text-[11px] font-medium text-center bg-red-950/30 py-2 rounded-lg border border-red-900/50 mt-2">{validationError}</p>
            )}
            <button
              onClick={handleCreateEscrow}
              disabled={isContractLoading || validationError !== null}
              className={`w-full py-3 rounded-xl font-bold mt-2 shadow-lg transition ${
                isContractLoading || validationError !== null
                  ? 'bg-[#151518] text-slate-500 border border-[#2a2a2e] cursor-not-allowed'
                  : 'bg-white hover:bg-slate-200 text-black shadow-white/10'
              }`}>
              {isContractLoading ? (loadingText || (lang === 'TR' ? '⏳ İşleniyor...' : '⏳ Processing...')) : (lang === 'TR' ? '🔒 Onayla ve Kilitle' : '🔒 Approve & Lock')}
            </button>
          </div>
        </div>
      </div>
    );
  };

  // [TR] Profil merkezi modalı — ayarlar, itibar, ilanlarım, aktif ve geçmiş sekmeleri
  // [EN] Profile center modal — settings, reputation, my ads, active and history tabs
  const renderProfileModal = () => {
    if (!showProfileModal) return null;
    if (!isConnected || !isAuthenticated) {
      setShowProfileModal(false);
      return null;
    }
    const myOrders = address ? orders.filter(o => o.makerFull?.toLowerCase() === address.toLowerCase()) : [];

    return (
      <div className="fixed inset-0 bg-[#060608]/90 backdrop-blur-sm flex items-end sm:items-center justify-center sm:p-4 z-[100]">
        <div className="bg-[#111113] border-t sm:border border-[#222] rounded-t-3xl sm:rounded-2xl w-full max-w-2xl shadow-2xl h-[85vh] sm:h-auto sm:max-h-[90vh] flex flex-col pb-16 sm:pb-0">
          <div className="flex justify-between items-center p-5 sm:p-6 border-b border-[#222] shrink-0">
            <h2 className="text-2xl font-bold text-white">{lang === 'TR' ? 'Profil Merkezi' : 'Profile Center'}</h2>
            <button onClick={() => setShowProfileModal(false)} className="text-slate-400 hover:text-white text-2xl leading-none">&times;</button>
          </div>

          <div className="flex border-b border-[#222] shrink-0 overflow-x-auto hide-scrollbar">
            {['ayarlar', 'itibar', 'ilanlarim', 'aktif', 'gecmis'].map(tab => (
              <button key={tab} onClick={() => setProfileTab(tab)} className={`px-4 py-3 text-sm font-medium capitalize transition whitespace-nowrap ${profileTab === tab ? 'text-emerald-400 border-b-2 border-emerald-400 bg-[#1a1a1f]/50' : 'text-slate-400 hover:text-white'}`}>
                {tab === 'ayarlar' ? (lang === 'TR' ? 'Ayarlar' : 'Settings') : tab === 'itibar' ? (lang === 'TR' ? 'İtibar' : 'Reputation') : tab === 'ilanlarim' ? (lang === 'TR' ? 'İlanlarım' : 'My Ads') : tab === 'aktif' ? (lang === 'TR' ? 'Aktif İşlemler' : 'Active Trades') : (lang === 'TR' ? 'Geçmiş' : 'History')}
              </button>
            ))}
          </div>

          <div className="overflow-y-auto p-6 flex-1">
            {profileTab === 'ayarlar' && (
              <div className="space-y-4 text-sm">
                {isBanned && (
                  <div className="bg-red-950/40 border border-red-900/50 p-4 rounded-xl flex items-start space-x-3">
                    <span className="text-2xl">🚫</span>
                    <div>
                      <p className="font-bold text-red-400">{lang === 'TR' ? 'Taker Kısıtlaması Aktif' : 'Taker Restriction Active'}</p>
                      <p className="text-red-300/80 text-xs mt-1">{lang === 'TR' ? 'Sadece Maker olarak ilan açabilirsiniz.' : 'You can only create listings as Maker.'}</p>
                    </div>
                  </div>
                )}
                <div className="bg-[#151518] p-4 rounded-xl border border-[#2a2a2e]">
                  <p className="text-slate-500 text-xs mb-1 uppercase tracking-widest font-bold">{lang === 'TR' ? 'Cüzdan Adresi' : 'Wallet Address'}</p>
                  <p className="font-mono text-white text-xs break-all">{address ? address : (lang === 'TR' ? 'Bağlı Değil' : 'Not Connected')}</p>
                </div>
                <form onSubmit={handleUpdatePII} className="bg-[#151518] p-4 rounded-xl border border-[#2a2a2e] space-y-3">
                  <p className="text-slate-300 text-sm font-bold">{lang === 'TR' ? 'Banka & İletişim Bilgileri' : 'Bank & Contact Info'}</p>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">{lang === 'TR' ? 'Banka Hesabı Sahibi (Ad Soyad)' : 'Bank Account Owner (Full Name)'}</label>
                    <input type="text" value={piiBankOwner} onChange={e => setPiiBankOwner(e.target.value)} placeholder={lang === 'TR' ? 'Adınız Soyadınız' : 'Your Full Name'} className="w-full bg-[#0c0c0e] text-white px-3 py-2 rounded-lg border border-[#222] outline-none text-sm" />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">IBAN</label>
                    <input type="text" value={piiIban} onChange={e => setPiiIban(e.target.value)} placeholder="TRXX XXXX XXXX XXXX XXXX XXXX XX" className="w-full bg-[#0c0c0e] text-white px-3 py-2 rounded-lg border border-[#222] outline-none font-mono text-sm" />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">{lang === 'TR' ? 'Telegram (Opsiyonel)' : 'Telegram (Optional)'}</label>
                    <div className="relative">
                      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">@</span>
                      <input type="text" value={piiTelegram} onChange={e => setPiiTelegram(e.target.value)} placeholder="kullanici_adiniz" className="w-full bg-[#0c0c0e] text-white pl-7 pr-3 py-2 rounded-lg border border-[#222] outline-none text-sm" />
                    </div>
                  </div>
                  <button type="submit" disabled={isContractLoading} className={`w-full py-2.5 rounded-xl font-bold text-sm transition ${isContractLoading ? 'bg-[#222] text-slate-500 cursor-not-allowed' : 'bg-emerald-600 hover:bg-emerald-500 text-white'}`}>
                    {isContractLoading ? (lang === 'TR' ? 'Kaydediliyor...' : 'Saving...') : (lang === 'TR' ? 'Bilgileri Kaydet' : 'Save Information')}
                  </button>
                  <p className="text-[10px] text-slate-500 text-center pt-3 border-t border-[#2a2a2e]">
                    🔒 {lang === 'TR' ? 'IBAN ve Telegram bilgileriniz AES-256 ile şifrelenir ve asla on-chain kaydedilmez.' : 'Your IBAN and Telegram are AES-256 encrypted and never saved on-chain.'}
                  </p>
                </form>
                <button
                  onClick={() => { disconnect(); setIsAuthenticated(false); setShowProfileModal(false); }}
                  className="w-full mt-4 py-2.5 rounded-xl font-bold text-sm bg-red-950/40 text-red-500 border border-red-900/50 hover:bg-red-900/80 hover:text-white transition">
                  {lang === 'TR' ? '🚪 Çıkış Yap / Cüzdanı Ayır' : '🚪 Disconnect / Logout'}
                </button>
              </div>
            )}

            {profileTab === 'itibar' && (
              <div className="space-y-3 text-sm">
                <p className="text-xs text-slate-500 mb-4 text-center italic">{lang === 'TR' ? 'Bu veriler doğrudan on-chain akıllı kontrattan okunur ve değiştirilemez.' : 'This data is read directly from the on-chain smart contract and cannot be altered.'}</p>
                {!userReputation ? (
                  <div className="text-center text-slate-500 animate-pulse">{lang === 'TR' ? 'İtibar verisi yükleniyor...' : 'Loading reputation data...'}</div>
                ) : (() => {
                  const { successful, failed, effectiveTier, bannedUntil, consecutiveBans, firstSuccessfulTradeAt } = userReputation;
                  const totalTrades = successful + failed;
                  const successRate = totalTrades > 0 ? Math.round((successful / totalTrades) * 100) : 100;
                  const TIER_REQUIREMENTS = {
                    1: { trades: 15, failed: 0 },
                    2: { trades: 50, failed: 1 },
                    3: { trades: 100, failed: 1 },
                    4: { trades: 200, failed: 0 },
                  };
                  const nextTier = effectiveTier + 1;
                  const nextTierReq = TIER_REQUIREMENTS[nextTier];
                  const progress = nextTierReq ? Math.min(100, (successful / nextTierReq.trades) * 100) : 100;

                  return (
                    <div className="space-y-4">
                      <div className="bg-[#151518] p-4 rounded-xl border border-[#2a2a2e]">
                        <div className="flex justify-between items-center text-xs text-slate-400 mb-2">
                          <span>{lang === 'TR' ? 'Başarı Oranı' : 'Success Rate'}</span>
                          <span>{totalTrades} {lang === 'TR' ? 'İşlem' : 'Trades'}</span>
                        </div>
                        <div className="w-full bg-[#0c0c0e] rounded-full h-2.5 border border-[#222]">
                          <div className="bg-gradient-to-r from-emerald-600 to-emerald-400 h-2.5 rounded-full" style={{ width: `${successRate}%` }}></div>
                        </div>
                        <p className="text-right text-lg font-bold text-emerald-400 mt-2">{successRate}%</p>
                      </div>
                      {nextTier <= 4 && (
                        <div className="bg-[#151518] p-4 rounded-xl border border-[#2a2a2e]">
                          <div className="flex justify-between items-center text-xs text-slate-400 mb-2">
                            <span>{lang === 'TR' ? `Tier ${nextTier} için İlerleme` : `Progress to Tier ${nextTier}`}</span>
                            <span className="font-mono">{successful} / {nextTierReq.trades}</span>
                          </div>
                          <div className="w-full bg-[#0c0c0e] rounded-full h-2.5 border border-[#222]">
                            <div className="bg-gradient-to-r from-purple-600 to-indigo-500 h-2.5 rounded-full transition-all duration-500" style={{ width: `${progress}%` }}></div>
                          </div>
                          <p className="text-xs text-slate-500 mt-2">
                            {lang === 'TR'
                              ? `Tier ${nextTier}'e ulaşmak için ${Math.max(0, nextTierReq.trades - successful)} başarılı işlem daha yapın.`
                              : `Complete ${Math.max(0, nextTierReq.trades - successful)} more successful trades to reach Tier ${nextTier}.`}
                          </p>
                        </div>
                      )}
                      <div className="grid grid-cols-2 gap-3">
                        <div className="bg-[#151518] p-3 rounded-xl border border-[#2a2a2e] text-center">
                          <p className="text-slate-500 text-[10px] font-bold tracking-widest">{lang === 'TR' ? 'EFEKTİF TIER' : 'EFFECTIVE TIER'}</p>
                          <p className="text-2xl font-bold text-white mt-1">T{effectiveTier}</p>
                        </div>
                        <div className="bg-[#151518] p-3 rounded-xl border border-[#2a2a2e] text-center">
                          <p className="text-slate-500 text-[10px] font-bold tracking-widest">{lang === 'TR' ? 'BAŞARILI' : 'SUCCESSFUL'}</p>
                          <p className="text-2xl font-bold text-emerald-400 mt-1">{successful}</p>
                        </div>
                        <div className="bg-[#151518] p-3 rounded-xl border border-[#2a2a2e] text-center">
                          <p className="text-slate-500 text-[10px] font-bold tracking-widest">{lang === 'TR' ? 'BAŞARISIZ' : 'FAILED'}</p>
                          <p className="text-2xl font-bold text-red-400 mt-1">{failed}</p>
                        </div>
                        <div className="bg-[#151518] p-3 rounded-xl border border-[#2a2a2e] text-center">
                          <p className="text-slate-500 text-[10px] font-bold tracking-widest">{lang === 'TR' ? 'ARDIŞIK YASAK' : 'CONSEC. BANS'}</p>
                          <p className="text-2xl font-bold text-white mt-1">{consecutiveBans}</p>
                        </div>
                      </div>
                      {firstSuccessfulTradeAt > 0 && new Date().getTime() / 1000 < firstSuccessfulTradeAt + 15 * 24 * 3600 && (
                        <div className="bg-[#151518] p-4 rounded-xl border border-[#2a2a2e]">
                          <p className="text-xs text-slate-400 mb-1">
                            {lang === 'TR' ? 'Tier 1 erişimi için 15 günlük aktiflik sürenizin dolmasına:' : 'Time left for 15-day active period for Tier 1:'}
                          </p>
                          <p className="text-sm font-bold text-yellow-500">
                            {Math.ceil((firstSuccessfulTradeAt + 15 * 24 * 3600 - new Date().getTime() / 1000) / (24 * 3600))} {lang === 'TR' ? 'gün kaldı' : 'days left'}
                          </p>
                        </div>
                      )}
                      {bannedUntil > 0 && new Date(bannedUntil * 1000) > new Date() && (
                        <div className="bg-red-950/30 p-3 rounded-xl border border-red-900/50">
                          <p className="text-red-400 text-xs font-medium">{lang === 'TR' ? 'Yasak Bitiş Tarihi' : 'Ban Ends On'}</p>
                          <p className="text-sm font-bold text-white mt-1">{new Date(bannedUntil * 1000).toLocaleString(lang === 'TR' ? 'tr-TR' : 'en-US')}</p>
                        </div>
                      )}
                      {consecutiveBans > 0 && (() => {
                        const now = Date.now() / 1000;
                        const cleanSlateTime = bannedUntil + (180 * 24 * 60 * 60);
                        const isEligible = now > cleanSlateTime && bannedUntil > 0;
                        const isBanActive = now < bannedUntil;
                        return (
                          <div className="bg-blue-950/20 p-4 rounded-xl border border-blue-900/40 text-center mt-4">
                            <p className="text-blue-400 text-xs font-bold mb-2">🛡️ {lang === 'TR' ? 'Temiz Sayfa Hakkı' : 'Clean Slate Right'}</p>
                            {isBanActive ? (
                              <p className="text-slate-400 text-[11px]">
                                {lang === 'TR' ? 'Cezanız devam ediyor. Ardışık yasak sayacınızı sıfırlamak için cezanız bittikten sonra 180 gün beklemelisiniz.' : 'Your ban is active. You must wait 180 days after your ban expires to reset your consecutive bans counter.'}
                              </p>
                            ) : isEligible ? (
                              <>
                                <p className="text-emerald-400 text-[11px] mb-3">
                                  {lang === 'TR' ? 'Tebrikler! Son yasağınızın üzerinden 180 gün geçti. Sicilinizi şimdi temizleyebilirsiniz.' : 'Congratulations! 180 days have passed since your last ban. You can clear your record now.'}
                                </p>
                                <button
                                  onClick={async () => {
                                    if (isContractLoading) return;
                                    try {
                                      setIsContractLoading(true);
                                      showToast(lang === 'TR' ? 'Sicil temizleme işlemi gönderiliyor...' : 'Sending record clear transaction...', 'info');
                                      await decayReputation(address);
                                      showToast(lang === 'TR' ? '✨ Siciliniz başarıyla temizlendi!' : '✨ Record successfully cleared!', 'success');
                                    } catch (err) {
                                      console.error('decayReputation error:', err);
                                      showToast(lang === 'TR' ? 'İşlem başarısız oldu.' : 'Transaction failed.', 'error');
                                    } finally {
                                      setIsContractLoading(false);
                                    }
                                  }}
                                  disabled={isContractLoading}
                                  className={`w-full py-2.5 rounded-lg font-bold text-xs transition ${isContractLoading ? 'bg-[#1a1a1f] text-slate-500 cursor-not-allowed border border-[#2a2a2e]' : 'bg-blue-600 hover:bg-blue-500 text-white shadow-[0_0_10px_rgba(37,99,235,0.3)]'}`}
                                >
                                  {isContractLoading ? (lang === 'TR' ? '⏳ İşlem Onaylanıyor...' : '⏳ Confirming...') : (lang === 'TR' ? '✨ Sicilimi Temizle' : '✨ Clear My Record')}
                                </button>
                              </>
                            ) : (
                              <p className="text-slate-400 text-[11px]">
                                {lang === 'TR' ? 'Ardışık yasak sayacınızı sıfırlamak için son cezanızın üzerinden 180 gün geçmesi gerekir.' : 'You must wait 180 days after your last ban to reset your consecutive bans counter.'}
                                <br/>
                                <span className="text-slate-300 font-bold mt-1 block">
                                  {lang === 'TR' ? 'Açılış Tarihi:' : 'Unlock Date:'} {new Date(cleanSlateTime * 1000).toLocaleDateString()}
                                </span>
                              </p>
                            )}
                          </div>
                        );
                      })()}
                    </div>
                  );
                })()}
              </div>
            )}

            {profileTab === 'ilanlarim' && (
              <div className="space-y-3">
                {myOrders.length > 0 ? myOrders.map(order => (
                  <div key={order.id} className={`bg-[#151518] border rounded-xl p-4 transition-all duration-200 ${confirmDeleteId === order.id ? 'border-red-900/60 bg-red-950/20' : 'border-[#2a2a2e] flex flex-col'}`}>
                    <div className="flex justify-between items-center">
                      <div>
                        <p className="font-bold text-white text-sm">{order.crypto} → {order.fiat}</p>
                        <p className="text-xs text-slate-400 mt-0.5">{order.rate} {order.fiat} · {order.min}–{order.max}</p>
                      </div>
                      {confirmDeleteId !== order.id && <button onClick={() => setConfirmDeleteId(order.id)} className="text-xs text-red-500 border border-red-900/40 hover:bg-red-900/20 px-3 py-1.5 rounded-lg transition font-medium">{lang === 'TR' ? 'Sil' : 'Delete'}</button>}
                    </div>
                    {confirmDeleteId === order.id && (
                      <div className="mt-3 pt-3 border-t border-red-900/40 flex gap-2">
                        <button onClick={() => handleDeleteOrder(order)} disabled={isContractLoading} className="flex-1 bg-red-600 hover:bg-red-500 text-white text-xs font-bold py-2 rounded-lg transition">{lang === 'TR' ? 'Evet, Sil' : 'Yes, Delete'}</button>
                        <button onClick={() => setConfirmDeleteId(null)} className="flex-1 bg-[#222] hover:bg-[#333] text-slate-300 text-xs font-bold py-2 rounded-lg transition">{lang === 'TR' ? 'İptal' : 'Cancel'}</button>
                      </div>
                    )}
                  </div>
                )) : <p className="text-center text-slate-500 text-xs mt-4">{lang === 'TR' ? 'İlan bulunamadı.' : 'No ads found.'}</p>}
              </div>
            )}

            {profileTab === 'aktif' && (
              <div className="space-y-3">
                <div className="flex gap-1 mb-4 bg-[#0a0a0c] p-1 rounded-lg border border-[#222]">
                  {['ALL', 'LOCKED', 'PAID', 'CHALLENGED'].map(f => (
                    <button
                      key={f}
                      onClick={() => setActiveTradesFilter(f)}
                      className={`flex-1 text-[10px] font-bold py-1.5 rounded transition ${activeTradesFilter === f ? 'bg-[#222] text-white' : 'text-slate-500 hover:text-slate-300'}`}
                    >
                      {f === 'ALL' ? (lang === 'TR' ? 'TÜMÜ' : 'ALL') : f}
                    </button>
                  ))}
                </div>
                {(() => {
                  const filteredEscrows = activeTradesFilter === 'ALL' ? activeEscrows : activeEscrows.filter(e => e.state === activeTradesFilter);
                  if (filteredEscrows.length === 0) {
                    return <p className="text-center text-slate-500 text-xs mt-4">{lang === 'TR' ? 'Bu duruma ait işlem bulunamadı.' : 'No trades found for this status.'}</p>;
                  }
                  return filteredEscrows.map((escrow, index) => (
                    <div key={`${escrow.id}-${index}`} className="bg-[#151518] border border-[#2a2a2e] rounded-xl p-4">
                      <div className="flex justify-between items-start mb-2">
                        <div>
                          <span className="font-mono text-emerald-400 font-bold">{escrow.id}</span>
                          <span className="text-[10px] text-slate-500 ml-2 uppercase border border-[#333] px-2 py-0.5 rounded">{escrow.role}</span>
                        </div>
                        <span className={`text-[10px] font-bold px-2 py-1 rounded-md border ${escrow.state === 'PAID' ? 'bg-emerald-900/20 border-emerald-900/50 text-emerald-400' : escrow.state === 'CHALLENGED' ? 'bg-red-900/20 border-red-900/50 text-red-500' : 'bg-slate-800 border-slate-700 text-slate-300'}`}>{escrow.state}</span>
                      </div>
                      <p className="text-white font-medium text-sm mb-1">{escrow.amount} <span className="text-slate-500 text-xs ml-1">({escrow.rawTrade.max.toFixed(2)} {escrow.rawTrade.fiat})</span></p>
                      <p className="text-xs text-slate-400 mb-3">Karşı Taraf: <span className="font-mono">{escrow.counterparty}</span></p>
                      <button onClick={() => {
                        setShowProfileModal(false);
                        setActiveTrade(escrow.rawTrade);
                        setUserRole(escrow.role);
                        setTradeState(escrow.state);
                        setCurrentView('tradeRoom');
                      }} className="w-full mt-3 bg-[#0c0c0e] hover:bg-[#222] text-white text-xs font-bold py-2.5 rounded-lg transition border border-[#2a2a2e]">
                        {lang === 'TR' ? 'Odaya Git →' : 'Go to Room →'}
                      </button>
                    </div>
                  ));
                })()}
              </div>
            )}

            {profileTab === 'gecmis' && (
              <div className="space-y-3 text-sm">
                {historyLoading && tradeHistory.length === 0 ? (
                  <div className="text-center text-slate-500 animate-pulse">{lang === 'TR' ? 'Geçmiş yükleniyor...' : 'Loading history...'}</div>
                ) : tradeHistory.length > 0 ? (
                  tradeHistory.map(tx => {
                    const statusMap = { RESOLVED: { text: lang === 'TR' ? 'Tamamlandı' : 'Resolved', color: 'emerald' }, CANCELED: { text: lang === 'TR' ? 'İptal Edildi' : 'Canceled', color: 'slate' }, BURNED: { text: lang === 'TR' ? 'Yakıldı' : 'Burned', color: 'red' } };
                    const displayStatus = statusMap[tx.status] || { text: tx.status, color: 'slate' };
                    const isMaker = tx.maker_address === address?.toLowerCase();
                    return (
                      <div key={tx._id} className="bg-[#151518] border border-[#2a2a2e] rounded-xl p-3 flex justify-between items-center">
                        <div>
                          <p className="font-mono text-[10px] text-slate-500">#{tx.onchain_escrow_id}</p>
                          <p className="text-white font-medium mt-0.5 text-xs"><span className={`mr-1 ${isMaker ? 'text-red-400' : 'text-emerald-400'}`}>{isMaker ? '→' : '←'}</span> {tx.financials.crypto_amount} {tx.financials.crypto_asset}</p>
                        </div>
                        <span className={`text-[10px] px-2 py-1 rounded font-bold text-${displayStatus.color}-400`}>{displayStatus.text}</span>
                      </div>
                    );
                  })
                ) : <p className="text-center text-slate-500 text-xs mt-4">{lang === 'TR' ? 'İşlem geçmişi bulunamadı.' : 'No trade history found.'}</p>}
                {tradeHistoryTotal > tradeHistoryLimit && (
                  <div className="flex justify-between items-center pt-4 border-t border-[#222]">
                    <button onClick={() => setTradeHistoryPage(p => p - 1)} disabled={tradeHistoryPage <= 1 || historyLoading} className="px-3 py-1.5 text-xs font-bold rounded bg-[#151518] text-slate-400 disabled:opacity-50 hover:bg-[#222]">←</button>
                    <span className="text-[10px] text-slate-500">{tradeHistoryPage} / {Math.ceil(tradeHistoryTotal / tradeHistoryLimit)}</span>
                    <button onClick={() => setTradeHistoryPage(p => p + 1)} disabled={tradeHistoryPage * tradeHistoryLimit >= tradeHistoryTotal || historyLoading} className="px-3 py-1.5 text-xs font-bold rounded bg-[#151518] text-slate-400 disabled:opacity-50 hover:bg-[#222]">→</button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  // ═══════════════════════════════════════════
  // 11. NAVİGASYON BİLEŞENLERİ
  //     Slim rail, context sidebar, mobile nav
  // ═══════════════════════════════════════════

  // [TR] Sol dar navigasyon çubuğu — yalnızca masaüstünde görünür
  // [EN] Left slim navigation rail — visible only on desktop
  const renderSlimRail = () => (
    <div className="hidden md:flex w-16 bg-black border-r border-[#1a1a1a] flex-col items-center py-6 justify-between z-50 shrink-0 shadow-2xl">
      <div className="space-y-6 flex flex-col items-center w-full">
        <div className="w-8 h-8 rounded bg-gradient-to-br from-white to-slate-400 flex items-center justify-center font-bold text-black mb-4 cursor-pointer" onClick={() => setCurrentView('home')}>
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="square" strokeLinejoin="miter" strokeWidth="3" d="M4 4h4v4H4zm12 0h4v4h-4zM4 16h4v4H4zm12 0h4v4h-4zM10 10h4v4h-4z" /></svg>
        </div>
        <button onClick={openSidebar} title={lang === 'TR' ? 'Filtreler' : 'Filters'} className={`w-10 h-10 flex items-center justify-center rounded-xl transition ${sidebarOpen ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-white hover:bg-[#111113]'}`}>☰</button>
        <button onClick={() => setCurrentView('home')} title={lang === 'TR' ? 'Ana Sayfa' : 'Home'} className={`w-10 h-10 flex items-center justify-center rounded-xl transition ${currentView === 'home' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-white hover:bg-[#111113]'}`}>🏠</button>
        <button onClick={() => setCurrentView('market')} title={lang === 'TR' ? 'Pazar Yeri' : 'Marketplace'} className={`w-10 h-10 flex items-center justify-center rounded-xl transition ${currentView === 'market' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-white hover:bg-[#111113]'}`}>🛒</button>
        <button onClick={() => setCurrentView('tradeRoom')} title={lang === 'TR' ? 'İşlem Odası' : 'Trade Room'} className={`w-10 h-10 flex items-center justify-center rounded-xl transition relative ${currentView === 'tradeRoom' ? 'bg-orange-600/20 text-orange-500' : 'text-slate-500 hover:text-white hover:bg-[#111113]'}`}>
          💼 {activeEscrows.length > 0 && <span className="absolute top-2 right-2 w-2 h-2 bg-orange-500 rounded-full animate-pulse"></span>}
        </button>
        <button onClick={() => { if (!isConnected || !isAuthenticated) { handleAuthAction(); return; } setProfileTab('gecmis'); setShowProfileModal(true); }} title={lang === 'TR' ? 'İşlem Geçmişi' : 'Trade History'} className="w-10 h-10 flex items-center justify-center rounded-xl text-slate-500 hover:text-white hover:bg-[#111113] transition">🗂️</button>
      </div>
      <div className="space-y-4 flex flex-col items-center w-full px-2">
        <button onClick={() => setLang(lang === 'TR' ? 'EN' : 'TR')} title={lang === 'TR' ? 'Dili Değiştir' : 'Change Language'} className="text-xs font-bold text-slate-400 hover:text-white mb-1">{lang}</button>
        <button onClick={handleAuthAction} title={isConnected && isAuthenticated ? (lang === 'TR' ? 'Profil Merkezi' : 'Profile Center') : (lang === 'TR' ? 'Cüzdan Bağla' : 'Connect Wallet')} className={`w-10 h-10 rounded-full border-2 flex items-center justify-center transition-all shadow-lg mx-auto ${isConnected && isAuthenticated ? 'border-emerald-500 bg-emerald-900/20 text-emerald-400 hover:bg-emerald-900/40 shadow-[0_0_10px_rgba(16,185,129,0.2)]' : 'border-[#2a2a2e] bg-[#111113] text-slate-400 hover:text-white hover:border-emerald-500/50 hover:bg-[#1a1a1f]'}`}>
          {isLoggingIn || !authChecked ? <span className="text-xs animate-spin">⚙️</span> : (isConnected && isAuthenticated ? <span className="text-base drop-shadow-[0_0_5px_rgba(16,185,129,0.8)]">👤</span> : <span className="text-base drop-shadow-[0_0_5px_rgba(255,255,255,0.5)]">👛</span>)}
        </button>
      </div>
    </div>
  );

  // [TR] Bağlamsal yan panel — 5 sn sonra kapanır, hover timer'ı sıfırlar.
  //      Filtreler, durum akordiyonu ve ilan oluşturma butonu içerir.
  // [EN] Context sidebar — closes after 5s, hover resets timer.
  //      Contains filters, status accordion and listing creation button.
  const renderContextSidebar = () => (
    <>
      {sidebarOpen && <div className="md:hidden fixed inset-0 bg-black/60 z-[55] backdrop-blur-sm transition-opacity" onClick={() => setSidebarOpen(false)} />}
      <div
        className={`fixed md:relative top-0 left-0 h-full bg-[#0c0c0e] border-r border-[#1a1a1a] flex flex-col z-[60] md:z-40 shrink-0 overflow-hidden transition-all duration-300 ease-in-out ${sidebarOpen ? 'w-[260px] p-5 opacity-100' : 'w-0 p-0 opacity-0'}`}
        onMouseEnter={openSidebar}
        onMouseLeave={() => {}}
      >
        <div className="relative mb-6">
          <span className="absolute left-3 top-2.5 text-slate-500 text-sm">🔍</span>
          <input type="number" value={searchAmount} onChange={e => setSearchAmount(e.target.value)} placeholder={lang === 'TR' ? 'Tutar Ara...' : 'Search...'} className="w-full bg-[#151518] text-white pl-9 pr-3 py-2.5 rounded-xl border border-[#2a2a2e] outline-none focus:border-emerald-500/50 text-sm transition" />
        </div>

        <div className="mb-8">
          <p className="text-[10px] font-bold text-slate-500 mb-3 tracking-widest">{lang === 'TR' ? 'PAZAR YERİ' : 'MARKETPLACE'}</p>
          <div className="space-y-1">
            <button onClick={() => { setFilterToken('ALL'); setCurrentView('market'); }} className={`w-full flex justify-between items-center px-3 py-2 rounded-lg text-sm transition ${filterToken === 'ALL' && currentView === 'market' ? 'bg-[#1a1a1f] text-white border border-[#2a2a2e]' : 'text-slate-400 hover:text-white hover:bg-[#1a1a1f]/50'}`}>
              <div className="flex items-center gap-2"><span className="text-slate-500">⛓️</span> {lang === 'TR' ? 'TÜM İLANLAR' : 'ALL LISTINGS'}</div>
              <span className="bg-[#222] text-[10px] px-2 py-0.5 rounded text-slate-300">{orders.length}</span>
            </button>
            <button onClick={() => { setFilterToken('USDT'); setCurrentView('market'); }} className={`w-full flex justify-between items-center px-3 py-2 rounded-lg text-sm transition ${filterToken === 'USDT' && currentView === 'market' ? 'bg-[#1a1a1f] text-white border border-[#2a2a2e]' : 'text-slate-400 hover:text-white hover:bg-[#1a1a1f]/50'}`}>
              <div className="flex items-center gap-2"><span className="text-emerald-500">₮</span> USDT</div>
              <span className="bg-[#222] text-[10px] px-2 py-0.5 rounded text-slate-300">{orders.filter(o => o.crypto === 'USDT').length}</span>
            </button>
            <button onClick={() => setFilterTier1(!filterTier1)} className={`w-full flex justify-between items-center px-3 py-2 rounded-lg text-sm transition ${filterTier1 ? 'bg-[#1a1a1f] text-yellow-500 border border-yellow-500/20' : 'text-slate-400 hover:text-white hover:bg-[#1a1a1f]/50'}`}>
              <div className="flex items-center gap-2"><span className="text-yellow-500/70">🛡️</span> {lang === 'TR' ? 'Tier 0 Filtresi' : 'Tier 0 Filter'}</div>
            </button>
          </div>
        </div>

        <div>
          <p className="text-[10px] font-bold text-slate-500 mb-3 tracking-widest">{lang === 'TR' ? 'DURUM' : 'STATUS'}</p>
          <div className="space-y-2">
            {['LOCKED', 'PAID', 'CHALLENGED'].map(status => {
              const count = activeEscrowCounts[status];
              const isExpanded = expandedStatus === status;
              const statusTrades = activeEscrows.filter(e => e.state === status);
              return (
                <div key={status} className="flex flex-col">
                  <button
                    onClick={() => setExpandedStatus(isExpanded ? null : status)}
                    className={`w-full flex justify-between items-center px-3 py-2 rounded-lg text-sm transition ${isExpanded ? 'bg-[#1a1a1f] text-white border border-[#2a2a2e]' : 'text-slate-400 hover:text-white hover:bg-[#1a1a1f]/50 border border-transparent'}`}
                  >
                    <div className="flex items-center gap-2">
                      <span className={status === 'CHALLENGED' ? 'text-red-500' : 'text-slate-500'}>
                        {status === 'LOCKED' ? '🔒' : status === 'PAID' ? '%' : '⚔️'}
                      </span>
                      {status}
                    </div>
                    {count > 0 && (
                      <span className={status === 'CHALLENGED' ? 'bg-red-900/40 text-red-400 text-[10px] font-bold px-2 py-0.5 rounded border border-red-900/50' : 'bg-[#222] text-[10px] px-2 py-0.5 rounded text-slate-300'}>
                        {status === 'CHALLENGED' ? 'Araf' : count}
                      </span>
                    )}
                  </button>
                  <div className={`overflow-hidden transition-all duration-300 ease-in-out ${isExpanded ? 'max-h-[500px] opacity-100 mt-2' : 'max-h-0 opacity-0'}`}>
                    {statusTrades.length > 0 ? (
                      <div className="pl-3 pr-1 py-1 space-y-2 border-l-2 border-[#222] ml-3">
                        {statusTrades.map(escrow => (
                          <div key={escrow.id} className="bg-[#111113] p-2.5 rounded-lg border border-[#2a2a2e] text-xs shadow-inner">
                            <div className="flex justify-between items-center mb-1.5">
                              <span className="font-mono text-emerald-400 font-bold">{escrow.id}</span>
                              <span className="text-[9px] text-slate-500 uppercase border border-[#333] px-1.5 py-0.5 rounded">{escrow.role}</span>
                            </div>
                            <p className="text-slate-300 mb-2 truncate">{escrow.amount} <span className="text-slate-500 ml-1">({escrow.rawTrade.max.toFixed(0)} {escrow.rawTrade.fiat})</span></p>
                            <button
                              onClick={() => {
                                setActiveTrade(escrow.rawTrade);
                                setUserRole(escrow.role);
                                setTradeState(escrow.state);
                                setCurrentView('tradeRoom');
                                setSidebarOpen(false);
                              }}
                              className="w-full bg-[#1a1a1f] hover:bg-[#222] text-white text-[10px] font-bold py-1.5 rounded transition border border-[#333]"
                            >
                              {lang === 'TR' ? 'Odaya Git →' : 'Go to Room →'}
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="pl-3 ml-3 border-l-2 border-[#222] py-2 text-xs text-slate-600 italic">
                        {lang === 'TR' ? 'Bu duruma ait işlem yok.' : 'No trades in this status.'}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="mt-auto pt-6 border-t border-[#1a1a1a]">
          <div className="flex bg-[#0c0c0e] rounded-lg p-1 border border-[#2a2a2e] mb-3">
            <button onClick={() => setLang('TR')} className={`flex-1 py-1.5 rounded-md text-xs font-bold transition ${lang === 'TR' ? 'bg-[#222] text-white' : 'text-slate-500 hover:text-white'}`}>🇹🇷 TR</button>
            <button onClick={() => setLang('EN')} className={`flex-1 py-1.5 rounded-md text-xs font-bold transition ${lang === 'EN' ? 'bg-[#222] text-white' : 'text-slate-500 hover:text-white'}`}>🇬🇧 EN</button>
          </div>
          <button onClick={handleOpenMakerModal} disabled={isPaused} className={`w-full py-3 bg-gradient-to-r ${isPaused ? 'from-slate-700 to-slate-600 cursor-not-allowed text-slate-400' : 'from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.3)] hover:shadow-[0_0_20px_rgba(16,185,129,0.5)] text-white'} rounded-xl text-sm font-bold transition-all flex items-center justify-center gap-2`}>
            <span className="text-lg leading-none">+</span> {lang === 'TR' ? 'YENİ İLAN AÇ' : 'CREATE AD'}
          </button>
        </div>
      </div>
    </>
  );

  // ═══════════════════════════════════════════
  // 12. SAYFA RENDER FONKSİYONLARI
  //     Home, Marketplace, Trade Room views
  // ═══════════════════════════════════════════

  // [TR] Ana sayfa — protokol açıklaması ve istatistik kartları
  // [EN] Home page — protocol description and stats cards
  const renderHome = () => (
    <div className="p-4 md:p-8 max-w-[1200px] w-full">
      <div className="mb-12">
        <h1 className="text-4xl md:text-5xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-300 to-slate-500 tracking-tight mb-3">
          {lang === 'TR' ? <>Sistem yargılamaz. <br/>Dürüstsüzlüğü pahalıya mal eder.</> : <>The system does not judge. <br/>It makes dishonesty expensive.</>}
        </h1>
        <p className="text-slate-500 text-sm max-w-lg">{lang === 'TR' ? 'Merkeziyetsiz, emanet tutmayan ve oracle-bağımsız eşten eşe escrow protokolü. Hakem yok, sadece matematik.' : 'Decentralized, non-custodial, and oracle-free P2P escrow protocol. No arbitrators, just math.'}</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 md:gap-4 mb-10">
        <div className="bg-[#111113] border border-[#222] p-4 md:p-5 rounded-2xl">
          <p className="text-slate-500 text-[10px] font-bold tracking-widest uppercase mb-2">{lang === 'TR' ? 'TOPLAM HACİM' : 'TOTAL VOL'}</p>
          <div className="flex items-baseline">
            <span className="text-2xl font-bold text-white">${((protocolStats?.total_volume_usdt ?? 0) / 1000).toFixed(1)}K</span>
            <StatChange value={protocolStats?.changes_30d?.total_volume_usdt_pct} />
          </div>
        </div>
        <div className="bg-[#111113] border border-[#222] p-4 md:p-5 rounded-2xl">
          <p className="text-slate-500 text-[10px] font-bold tracking-widest uppercase mb-2">{lang === 'TR' ? 'BAŞARILI İŞLEM' : 'SUCCESS TRADES'}</p>
          <div className="flex items-baseline">
            <span className="text-2xl font-bold text-white">{(protocolStats?.completed_trades ?? 0).toLocaleString()}</span>
            <StatChange value={protocolStats?.changes_30d?.completed_trades_pct} />
          </div>
        </div>
        <div className="bg-[#111113] border border-[#222] p-4 md:p-5 rounded-2xl">
          <p className="text-slate-500 text-[10px] font-bold tracking-widest uppercase mb-2">{lang === 'TR' ? 'AKTİF İLAN' : 'ACTIVE ADS'}</p>
          <span className="text-2xl font-bold text-white">{(protocolStats?.active_listings ?? 0).toLocaleString()}</span>
        </div>
        <div className="bg-[#111113] border border-[#222] p-4 md:p-5 rounded-2xl">
          <p className="text-slate-500 text-[10px] font-bold tracking-widest uppercase mb-2">{lang === 'TR' ? 'ORT. SÜRE' : 'AVG TIME'}</p>
          <span className="text-2xl font-bold text-yellow-500">{protocolStats?.avg_trade_hours ?? '—'}s</span>
        </div>
        <div className="bg-[#1a0a0a] border border-[#4a1010] p-4 md:p-5 rounded-2xl relative overflow-hidden group">
          <div className="absolute -right-4 -bottom-4 text-red-500/10 text-6xl group-hover:scale-110 transition-transform">🔥</div>
          <p className="text-red-500 text-[10px] font-bold tracking-widest uppercase mb-2">{lang === 'TR' ? 'ERİYEN HAZİNE' : 'BURNED BONDS'}</p>
          <div className="flex items-baseline relative z-10">
            <span className="text-2xl font-bold text-red-400 drop-shadow-[0_0_8px_rgba(248,113,113,0.5)]">${(protocolStats?.burned_bonds_usdt ?? 0).toFixed(0)}</span>
          </div>
        </div>
      </div>

      {statsError && (
        <div className="col-span-2 md:col-span-5 text-center py-4 text-slate-500 text-xs">
          {lang === 'TR' ? 'İstatistik verisi alınamadı.' : 'Failed to load stats.'}
          <button onClick={fetchStats} className="ml-2 text-emerald-400 hover:underline">
            {lang === 'TR' ? 'Tekrar dene' : 'Retry'}
          </button>
        </div>
      )}
    </div>
  );

  // [TR] Pazar yeri — ilan listesi, filtreler, test faucet butonları
  // [EN] Marketplace — listing list, filters, test faucet buttons
  const renderMarket = () => (
    <div className="p-4 md:p-8 max-w-[1200px] w-full">
      <div className="mb-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <h2 className="text-xl font-bold text-white">{lang === 'TR' ? 'Pazar Yeri' : 'Marketplace'}</h2>
        <div className="flex gap-3 w-full md:w-auto">
          <button onClick={() => handleMint('USDT')} disabled={isContractLoading} className="flex-1 md:flex-none px-4 py-2 bg-[#111113] border border-[#222] hover:bg-[#1a1a1f] rounded-xl text-xs sm:text-sm font-bold text-emerald-400 transition shadow-lg flex items-center justify-center gap-2">
            {isContractLoading && loadingText.includes('USDT') ? '⏳' : '🚰'} {lang === 'TR' ? 'Test USDT Al' : 'Get Test USDT'}
          </button>
          <button onClick={() => handleMint('USDC')} disabled={isContractLoading} className="flex-1 md:flex-none px-4 py-2 bg-[#111113] border border-[#222] hover:bg-[#1a1a1f] rounded-xl text-xs sm:text-sm font-bold text-blue-400 transition shadow-lg flex items-center justify-center gap-2">
            {isContractLoading && loadingText.includes('USDC') ? '⏳' : '🚰'} {lang === 'TR' ? 'Test USDC Al' : 'Get Test USDC'}
          </button>
        </div>
      </div>

      <div className="space-y-3">
        {loading ? (
          <div className="p-8 text-center text-slate-500 animate-pulse">{lang === 'TR' ? 'Yükleniyor...' : 'Loading...'}</div>
        ) : filteredOrders.length > 0 ? (
          filteredOrders.map((order) => {
            const effectiveUserTier = userReputation?.effectiveTier ?? 0;
            const isMyOwnAd    = address && order.makerFull?.toLowerCase() === address.toLowerCase();
            const isTierLocked = isConnected && isAuthenticated && order.tier > effectiveUserTier;
            const canTakeOrder = isConnected && isAuthenticated && !isMyOwnAd && !isTierLocked && !isPaused;
            const tokenAddr    = SUPPORTED_TOKEN_ADDRESSES[order.crypto || 'USDT'];
            const isTokenConfigured = Boolean(tokenAddr);
            const isCorrectChain    = [8453, 84532, 31337].includes(chainId);
            const isFunded          = sybilStatus ? sybilStatus.funded : true;
            const isCooldownOk      = sybilStatus ? sybilStatus.cooldownOk : true;
            const finalCanTakeOrder = canTakeOrder && isCooldownOk && isFunded && !isPaused && isTokenConfigured && isCorrectChain;

            return (
              <div key={order.id} className="bg-[#111113] hover:bg-[#151518] border border-[#222] p-4 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between transition-colors group relative gap-4 md:gap-0">
                <div className="flex items-center gap-4 w-full md:w-1/3">
                  <div className="w-10 h-10 rounded-full bg-gradient-to-br from-emerald-500/20 to-emerald-900/20 border border-emerald-500/30 flex items-center justify-center text-emerald-500 shrink-0">₮</div>
                  <div className="relative group/tooltip">
                    <p className="text-white font-medium text-sm cursor-help">{order.maker}</p>
                    <p className="text-xs text-slate-500">{order.rate} {order.fiat} / 1 {order.crypto}</p>
                    <div className="absolute left-0 sm:-left-4 md:left-1/2 md:-translate-x-1/2 bottom-full mb-2 hidden group-hover/tooltip:block z-50">
                      <div className="bg-[#111] border border-[#333] p-5 rounded-2xl shadow-2xl w-64 backdrop-blur-xl">
                        <p className="text-[10px] text-slate-400 mb-3 tracking-widest">{lang === 'TR' ? 'SATICI PROFİLİ' : 'SELLER PROFILE'}</p>
                        <div className="flex items-center gap-4 mb-4">
                          <div className="w-16 h-16 rounded-full border-[3px] border-emerald-500/30 flex items-center justify-center relative">
                            <span className="text-emerald-400 font-bold text-xl">{order.successRate}%</span>
                            <svg className="absolute inset-0 w-full h-full -rotate-90"><circle cx="50%" cy="50%" r="46%" fill="none" stroke="#10b981" strokeWidth="6" strokeDasharray="100 100" strokeDashoffset={`${100 - order.successRate}`}/></svg>
                          </div>
                          <div>
                            <p className="text-[10px] text-slate-400 font-bold">{lang === 'TR' ? 'BAŞARI ORANI' : 'SUCCESS RATE'}</p>
                            <p className="text-xl font-bold text-emerald-400">{order.successRate}%</p>
                          </div>
                        </div>
                        <div className="space-y-2 text-xs border-t border-[#333] pt-3">
                          <div className="flex justify-between"><span className="text-slate-500">{lang === 'TR' ? 'SATIŞ HACMİ' : 'TRADE VOL'}</span><span className="text-white font-mono">{order.txCount} Tx</span></div>
                          <div className="flex justify-between"><span className="text-slate-500">{lang === 'TR' ? 'TIER DÜZEYİ' : 'TIER LEVEL'}</span><span className="text-yellow-500 font-bold">T{order.tier} 🛡️</span></div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="w-full md:w-1/3 text-left md:text-center border-t border-[#222] md:border-none pt-3 md:pt-0">
                  <p className="text-sm font-bold text-slate-300">{order.min} - {order.max} {order.fiat}</p>
                  <p className="text-[10px] text-emerald-500/80 mt-0.5 uppercase tracking-wider">{order.bond} {lang === 'TR' ? 'Teminat' : 'Bond'}</p>
                </div>

                <div className="w-full md:w-1/3 flex flex-col items-start md:items-end justify-center relative">
                  <button onClick={() => handleStartTrade(order)} disabled={!finalCanTakeOrder || isContractLoading} className={`w-full md:w-auto px-6 py-2.5 rounded-xl font-bold text-sm transition flex items-center justify-center gap-2 ${!finalCanTakeOrder ? 'bg-[#1a1a1f] text-slate-500 border border-[#2a2a2e] cursor-not-allowed' : 'bg-white text-black hover:bg-slate-200 shadow-[0_0_15px_rgba(255,255,255,0.1)]'}`}>
                    {isPaused            ? <><span>⏸️</span> {lang === 'TR' ? 'Bakımda' : 'Paused'}</> :
                     !isCorrectChain     ? <><span>⛓️</span> {lang === 'TR' ? 'Yanlış Ağ' : 'Wrong Network'}</> :
                     !isTokenConfigured  ? <><span>⚙️</span> {lang === 'TR' ? 'Token Ayarlanmadı' : 'Token Not Set'}</> :
                     !canTakeOrder       ? <><span>🔒</span> {lang === 'TR' ? 'Kilitli' : 'Locked'}</> :
                     !isFunded           ? <><span>⚠️</span> {lang === 'TR' ? 'Bakiye Yetersiz' : 'Low Balance'}</> :
                     // [TR] Cooldown süresini göstermek yerine sade etiket kullanılıyor
                     // [EN] Using simple label instead of showing cooldown duration
                     !isCooldownOk       ? <><span>⏳</span> {lang === 'TR' ? 'Cooldown Aktif' : 'Cooldown Active'}</> :
                     (isContractLoading  ? (loadingText || (lang === 'TR' ? '⏳ İşleniyor...' : '⏳ Processing...')) : (lang === 'TR' ? 'Satın Al' : 'Buy'))}
                  </button>
                  {!isFunded && isConnected && canTakeOrder && !isPaused && (
                    <p className="text-[10px] text-red-500 mt-2 text-center md:text-right w-full leading-tight">
                      ⚠️ Anti-Spam: {lang === 'TR' ? 'İşlem yapabilmek için cüzdanınızda en az 0.001 ETH bulunmalıdır.' : 'You must have at least 0.001 ETH in your wallet to trade.'}
                    </p>
                  )}
                </div>
              </div>
            );
          })
        ) : (
          <div className="p-8 text-center text-slate-500">{lang === 'TR' ? 'İlan bulunamadı.' : 'No ads found.'}</div>
        )}
      </div>
    </div>
  );

  // [TR] İşlem odası — LOCKED/PAID/CHALLENGED durumlarına göre taker/maker aksiyonlarını gösterir.
  //      Bleeding Escrow görsel barı, zamanlayıcılar, iptal/serbest bırakma ve PII bölümü içerir.
  // [EN] Trade room — shows taker/maker actions based on LOCKED/PAID/CHALLENGED state.
  //      Contains Bleeding Escrow visual bar, timers, cancel/release and PII section.
  const renderTradeRoom = () => {
    const isChallenged = tradeState === 'CHALLENGED';
    const isTaker = userRole === 'taker';
    const isMaker = userRole === 'maker';

    const rawCryptoAmt = ((activeTrade?.max || 0) / (activeTrade?.rate || 1));
    const protocolFee  = rawCryptoAmt * 0.001;
    const netAmount    = rawCryptoAmt - protocolFee;
    const asset        = activeTrade?.crypto || 'USDT';
    const feeBreakdownText = lang === 'TR'
      ? `Kilitli: ${rawCryptoAmt.toFixed(2)} ${asset} | Protokol Kesintisi: ${protocolFee.toFixed(4)} ${asset} | Net Alınacak: ${netAmount.toFixed(2)} ${asset}`
      : `Locked: ${rawCryptoAmt.toFixed(2)} ${asset} | Protocol Fee: ${protocolFee.toFixed(4)} ${asset} | Net to Receive: ${netAmount.toFixed(2)} ${asset}`;

    return (
      <div className="p-4 md:p-8 max-w-[900px] w-full mx-auto relative mt-6 md:mt-0">
        <button onClick={() => setCurrentView('market')} className="absolute -top-2 md:-top-4 left-4 md:left-8 text-slate-500 hover:text-white text-sm transition">← {lang === 'TR' ? 'Pazar Yerine Dön' : 'Go Back'}</button>

        <div className={`border rounded-2xl p-5 md:p-8 shadow-2xl transition-colors duration-700 ${isChallenged ? 'bg-[#1a0f0f] border-red-900/40' : 'bg-[#111113] border-[#222]'}`}>
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between mb-8 border-b border-[#222] pb-6 gap-4 md:gap-0">
            <div>
              <p className="text-slate-500 text-xs tracking-widest mb-1">{lang === 'TR' ? 'İŞLEM ODASI' : 'TRADE ROOM'}: {activeTrade?.id}</p>
              <h2 className="text-2xl font-bold text-white flex flex-col sm:flex-row items-start sm:items-center gap-3">
                {activeTrade?.max || '0.00'} {activeTrade?.fiat}
                <span className={`text-xs px-3 py-1 rounded-full border ${isChallenged ? 'bg-red-900/20 text-red-500 border-red-900' : 'bg-emerald-900/20 text-emerald-500 border-emerald-900'}`}>{isChallenged ? (lang === 'TR' ? 'Araf Fazı' : 'Purgatory') : tradeState}</span>
              </h2>
            </div>
            <div className="text-left md:text-right w-full md:w-auto border-t border-[#222] md:border-none pt-4 md:pt-0">
              <p className="text-slate-500 text-xs">{lang === 'TR' ? 'KARŞI TARAF' : 'COUNTERPARTY'}</p>
              <p className="text-white font-mono">{activeTrade?.maker || '0x...'}</p>
            </div>
          </div>

          {/* Bleeding Escrow görsel barı — yalnızca CHALLENGED state'inde gösterilir */}
          {isChallenged && (
            <div className="mb-8 md:mb-10 p-4 md:p-6 bg-[#0a0505] border border-red-950 rounded-xl relative overflow-hidden">
              <div className="flex justify-between text-xs font-bold mb-3">
                <span className="text-red-500">MAKER BOND</span>
                <span className="text-orange-500">TAKER BOND</span>
              </div>
              {(() => {
                const myBond       = bleedingAmounts ? (isTaker ? Number(bleedingAmounts.takerBondRemaining) : Number(bleedingAmounts.makerBondRemaining)) : null;
                const opponentBond = bleedingAmounts ? (isTaker ? Number(bleedingAmounts.makerBondRemaining) : Number(bleedingAmounts.takerBondRemaining)) : null;
                const myBondOrig   = myBond       !== null ? Math.max(myBond, 1)       : 1;
                const oppBondOrig  = opponentBond !== null ? Math.max(opponentBond, 1)  : 1;
                const myPct        = myBond       !== null ? Math.round((myBond       / myBondOrig)  * 100) : 40;
                const opponentPct  = opponentBond !== null ? Math.round((opponentBond / oppBondOrig)  * 100) : 35;
                const decayedTotal = bleedingAmounts ? Number(bleedingAmounts.totalDecayed) : 0;
                return (
                  <>
                    <div className="w-full h-3 bg-[#111] rounded-full flex relative border border-[#222]">
                      <div className="h-full bg-gradient-to-r from-red-700 to-red-500 rounded-l-full relative transition-all duration-500" style={{width: `${isMaker ? myPct : opponentPct}%`}}>
                        <div className="absolute right-0 top-1/2 -translate-y-1/2 w-4 h-4 bg-red-500 rounded-full blur-sm"></div>
                      </div>
                      <div className="flex-1 bg-transparent border-y border-red-900/30 flex items-center justify-center overflow-hidden">
                        <div className="w-full h-px bg-red-500/20 shadow-[0_0_10px_red] animate-pulse"></div>
                      </div>
                      <div className="h-full bg-gradient-to-l from-orange-700 to-orange-500 rounded-r-full relative transition-all duration-500" style={{width: `${isTaker ? myPct : opponentPct}%`}}>
                        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-4 h-4 bg-orange-500 rounded-full blur-sm"></div>
                      </div>
                    </div>
                    <div className="flex flex-col mt-4 space-y-2 relative">
                      <div className="w-full flex justify-between">
                        <span className="text-red-500/50 text-[10px] font-mono">{bleedingTimer.isFinished ? '00:00:00' : `${String(bleedingTimer.hours).padStart(2,'0')}:${String(bleedingTimer.minutes).padStart(2,'0')}:${String(bleedingTimer.seconds).padStart(2,'0')}`}</span>
                        <span className="text-orange-500/50 text-[10px] font-mono">{bleedingTimer.isFinished ? '00:00:00' : `${String(bleedingTimer.hours).padStart(2,'0')}:${String(bleedingTimer.minutes).padStart(2,'0')}:${String(bleedingTimer.seconds).padStart(2,'0')}`}</span>
                      </div>
                      <div className="text-center w-full">
                        <p className="text-red-400 font-bold text-sm drop-shadow-[0_0_5px_red]">{lang === 'TR' ? 'Yanan Toplam:' : 'Total Burned:'} {(decayedTotal / 1e6).toFixed(4)} USDT 🔥</p>
                      </div>
                    </div>
                  </>
                );
              })()}
              <div className="mt-8 flex items-center justify-center gap-2 text-xs text-slate-500">
                <span className="text-emerald-500">🔒</span> {lang === 'TR' ? 'Ana Para Güvende:' : 'Principal Safe:'} <span className="font-mono text-emerald-400">{principalProtectionTimer.isFinished ? 'Bitti' : `${principalProtectionTimer.days}g ${principalProtectionTimer.hours}s`}</span>
              </div>
            </div>
          )}

          <div className="space-y-6">
            {/* LOCKED state aksiyon paneli */}
            {tradeState === 'LOCKED' && (
              <div className="text-center py-6">
                <div className="w-14 h-14 bg-blue-500/10 text-blue-500 border border-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4 text-2xl">🔒</div>
                <h2 className="text-xl md:text-2xl font-bold text-white mb-2">{lang === 'TR' ? 'USDT Kilitlendi' : 'USDT Locked'}</h2>
                {isTaker ? (
                  <div className="w-full max-w-sm mt-4 space-y-3 mx-auto">
                    <div className="relative">
                      <input type="file" onChange={handleFileUpload} accept="image/*,.pdf" className="hidden" id="receipt-upload" />
                      <label htmlFor="receipt-upload" className="w-full bg-[#0a0a0c] text-white px-4 py-3 rounded-xl border border-[#333] mb-4 text-sm flex items-center justify-center cursor-pointer hover:border-blue-500/50 transition">
                        {paymentIpfsHash ? (lang === 'TR' ? '✅ Yüklendi (Hash: ' + paymentIpfsHash.slice(0,8) + '...)' : '✅ Uploaded') : (lang === 'TR' ? '📎 Dekont Yükle' : '📎 Upload Receipt')}
                      </label>
                      <p className="text-[10px] text-slate-500 mt-1 mb-4 text-center">
                        {lang === 'TR' ? 'Dekontunuz AES-256 ile şifrelenir ve işlem bitince kalıcı olarak silinir.' : 'Receipt is AES-256 encrypted and permanently deleted after trade.'}
                      </p>
                    </div>
                    <button onClick={handleReportPayment} disabled={isContractLoading || !paymentIpfsHash.trim()} className={`w-full py-3 rounded-xl font-bold transition ${isContractLoading || !paymentIpfsHash.trim() ? 'bg-[#1a1a1f] text-slate-500 cursor-not-allowed border border-[#2a2a2e]' : 'bg-blue-600 hover:bg-blue-500 text-white shadow-[0_0_15px_rgba(37,99,235,0.2)]'}`}>
                      {isContractLoading ? '⏳...' : (lang === 'TR' ? '✅ Ödemeyi Bildirdim' : '✅ Report Payment')}
                    </button>
                  </div>
                ) : (
                  <div className="flex flex-col items-center">
                    <p className="text-slate-500 mb-6 text-sm animate-pulse">{lang === 'TR' ? 'Alıcının transferi bekleniyor...' : 'Waiting for buyer transfer...'}</p>
                    {isMaker && (
                      <div className="w-full max-w-md mt-2 mx-auto p-4 bg-[#1a0f0f] border border-red-900/30 rounded-xl text-left">
                        <p className="text-xs text-red-400 font-bold mb-1">⚠️ {lang === 'TR' ? 'ÜÇGEN DOLANDIRICILIK ÖNLEMİ' : 'TRIANGULATION FRAUD PREVENTION'}</p>
                        <p className="text-sm text-slate-300 mb-2">
                          {lang === 'TR' ? 'Alıcının Doğrulanmış İsmi:' : "Buyer's Verified Name:"} <span className="font-bold text-white">{takerName || (lang === 'TR' ? 'Yükleniyor...' : 'Loading...')}</span>
                        </p>
                        <p className="text-[11px] text-slate-500 leading-tight">
                          {lang === 'TR' ? 'Gelen paranın gönderici ismi ile bu ismin KESİNLİKLE eşleştiğini teyit ediniz. Eşleşmiyorsa parayı iade edip işlemi iptal edin.' : 'Ensure the sender name on the payment EXACTLY matches this name. If not, refund and cancel.'}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* PAID state aksiyon paneli */}
            {tradeState === 'PAID' && (
              <div className="text-center py-4 flex flex-col items-center">
                <h2 className="text-lg md:text-xl font-bold text-emerald-400 mb-2">{lang === 'TR' ? 'Ödeme Bildirildi' : 'Payment Reported'}</h2>
                <div className="w-full max-w-sm bg-[#0a0a0c] border border-[#222] rounded-2xl p-4 mb-6">
                  <p className="text-xs text-slate-500 mb-1 uppercase font-bold">Grace Period</p>
                  <div className="text-4xl sm:text-5xl font-mono font-bold text-white tracking-wider">
                    {gracePeriodTimer.isFinished ? '00:00:00' : `${String(gracePeriodTimer.hours + gracePeriodTimer.days * 24).padStart(2, '0')}:${String(gracePeriodTimer.minutes).padStart(2, '0')}:${String(gracePeriodTimer.seconds).padStart(2, '0')}`}
                  </div>
                </div>
                {isTaker ? (
                  <div className="w-full max-w-md flex flex-col items-center">
                    <p className="text-slate-400 text-sm mb-4">{lang === 'TR' ? 'Satıcının onayı bekleniyor.' : 'Waiting for seller release.'}</p>
                    {(() => {
                      if (!activeTrade?.paidAt) return null;
                      if (activeTrade.pingedAt) {
                        const autoReleaseAt = new Date(new Date(activeTrade.pingedAt).getTime() + 24 * 3600 * 1000);
                        const canAutoRelease = new Date() > autoReleaseAt;
                        if (canAutoRelease) {
                          return (
                            <div className="w-full mt-2 flex flex-col items-center">
                              <p className="text-[11px] text-red-400 font-bold mb-1 text-center leading-tight">
                                {lang === 'TR' ? 'Dikkat: Satıcı pasif kaldığı için her iki tarafın teminatından %2 ihmal cezası kesilecektir (Maker: %2, Taker: %2).' : 'Warning: Due to maker inaction, a 2% negligence penalty will be deducted from both parties\' bonds (Maker: 2%, Taker: 2%).'}
                              </p>
                              <button onClick={() => handleAutoRelease(activeTrade.onchainId)} disabled={isContractLoading} className="w-full text-sm font-bold py-3 rounded-xl transition bg-emerald-600/20 text-emerald-400 border border-emerald-500/40 hover:bg-emerald-500 hover:text-white shadow-lg">
                                {isContractLoading ? '...' : (lang === 'TR' ? '✅ Fonları Otomatik Serbest Bırak' : '✅ Auto-Release Funds')}
                              </button>
                            </div>
                          );
                        }
                        return <div className="mt-2 text-center text-xs text-emerald-400 bg-emerald-900/20 p-3 rounded-lg border border-emerald-900/50 w-full"><p className="font-bold">✓ {lang === 'TR' ? 'Satıcı Uyarıldı' : 'Maker Pinged'}</p></div>;
                      }
                      const gracePeriodEnds = new Date(new Date(activeTrade.paidAt).getTime() + 48 * 3600 * 1000);
                      const canPing = new Date() > gracePeriodEnds;
                      if (activeTrade.challengePingedAt) {
                        return (
                          <div className="w-full mt-2 flex flex-col items-center">
                            <button disabled className="w-full text-sm font-bold py-3 rounded-xl transition bg-[#1a1a1f] text-slate-500 border border-[#2a2a2e] cursor-not-allowed">
                              {lang === 'TR' ? '🔔 Satıcıyı Uyar' : '🔔 Ping Maker'}
                            </button>
                            <p className="text-[11px] text-red-400 mt-2 text-center leading-tight">
                              ⚠️ {lang === 'TR' ? 'Satıcı itiraz uyarı sürecini başlattı. Artık otomatik serbest bırakma (Auto-Release) yolunu kullanamazsınız.' : 'Maker has initiated the challenge warning process. You can no longer use Auto-Release.'}
                            </p>
                          </div>
                        );
                      }
                      return <button onClick={() => handlePingMaker(activeTrade.onchainId)} disabled={!canPing || isContractLoading} className={`w-full mt-2 text-sm font-bold py-3 rounded-xl transition ${!canPing || isContractLoading ? 'bg-[#1a1a1f] text-slate-500 border border-[#2a2a2e] cursor-not-allowed' : 'bg-orange-600/20 text-orange-400 border border-orange-500/40 hover:bg-orange-500 hover:text-white'}`}>{isContractLoading ? '...' : canPing ? (lang === 'TR' ? '🔔 Satıcıyı Uyar' : '🔔 Ping Maker') : (lang === 'TR' ? '⏱️ Onay Bekleniyor' : '⏱️ Awaiting Confirmation')}</button>;
                    })()}
                  </div>
                ) : (
                  <div className="w-full max-w-md flex flex-col space-y-4">
                    <label className="flex items-start space-x-3 p-3 md:p-4 bg-[#1a0f0f] border border-red-900/30 rounded-xl cursor-pointer text-left">
                      <input type="checkbox" checked={chargebackAccepted} onChange={(e) => handleChargebackAck(e.target.checked)} className="mt-1 w-4 h-4 accent-emerald-500 rounded bg-[#0a0a0c] border-[#333]" />
                      <span className="text-xs text-slate-400"><strong className="text-red-500">{lang === 'TR' ? 'UYARI:' : 'WARNING:'}</strong> {lang === 'TR' ? 'Paranın farklı isimli bir hesaptan gelmediğini ve Chargeback riskini anladığımı kabul ediyorum.' : 'I confirm the funds came from the correct name and understand the Chargeback risk.'}</span>
                    </label>
                    <div className="w-full flex flex-col gap-2">
                      <div className="text-center p-2 bg-[#0c0c0e] rounded-xl border border-[#222]">
                        <p className="text-[10px] text-slate-400 font-mono">{feeBreakdownText}</p>
                      </div>
                      <div className="flex flex-col sm:flex-row justify-center gap-3">
                        <button disabled={!chargebackAccepted || isContractLoading} onClick={handleRelease} className={`w-full sm:w-auto px-8 py-3 rounded-xl font-bold transition ${chargebackAccepted && !isContractLoading ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.2)]' : 'bg-[#1a1a1f] text-slate-500 cursor-not-allowed border border-[#2a2a2e]'}`}>
                          {isContractLoading ? (lang === 'TR' ? '⏳ İşleniyor...' : '⏳ Processing...') : (lang === 'TR' ? 'Serbest Bırak' : 'Release USDT')}
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Ortak aksiyon paneli (iptal + serbest bırakma) — tüm aktif durumlarda gösterilir */}
            {['LOCKED', 'PAID', 'CHALLENGED'].includes(tradeState) && (
              <div className="mt-6 bg-[#0c0c0e] border border-[#222] rounded-xl p-4">
                <div className="mb-3 text-center p-2 bg-[#111113] rounded-lg border border-[#2a2a2e]">
                  <p className="text-[10px] text-slate-400 font-mono">{feeBreakdownText}</p>
                </div>
                {cancelStatus === null && (
                  <>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {isChallenged && isMaker && (
                        <button onClick={handleRelease} disabled={isContractLoading} className={`w-full bg-[#0a0a0c] border border-emerald-500/30 text-emerald-500 p-3 rounded-xl font-bold text-sm transition ${isContractLoading ? 'opacity-50 cursor-not-allowed' : 'hover:bg-emerald-500 hover:text-white'}`}>
                          🤝 {lang === 'TR' ? 'Serbest Bırak' : 'Release'}
                        </button>
                      )}
                      <button onClick={() => {
                        const msg = tradeState === 'LOCKED'
                          ? (lang === 'TR' ? 'LOCKED aşamasında (henüz ödeme bildirilmeden) iptaller kesintisizdir. Onaylıyor musunuz?' : 'Cancel in LOCKED state has zero fees. Confirm?')
                          : (lang === 'TR' ? 'Karşılıklı iptal durumunda standart protokol ücreti kesilecektir. Onaylıyor musunuz?' : 'Standard protocol fees will be deducted upon mutual cancellation. Confirm?');
                        if (window.confirm(msg)) handleProposeCancel();
                      }} className={`w-full bg-[#0a0a0c] border border-orange-500/30 text-orange-500 p-3 rounded-xl font-bold text-sm hover:bg-orange-500 hover:text-white transition ${!(isChallenged && isMaker) ? 'sm:col-span-2' : ''}`}>
                        ↩️ {lang === 'TR' ? 'İptal Teklif Et' : 'Propose Cancel'}
                      </button>
                    </div>
                    <p className="text-[10px] text-slate-500 text-center mt-3">
                      {lang === 'TR' ? 'Not: İptal onaylandığında her iki taraftan protokol ücreti kesilir.' : 'Note: Protocol fee is deducted from both parties upon cancel.'}
                    </p>
                  </>
                )}
                {cancelStatus === 'proposed_by_me' && (
                  <div className="py-3 px-4 bg-orange-900/10 border border-orange-500/20 rounded-xl flex items-center justify-center gap-3">
                    <div className="w-4 h-4 border-2 border-orange-400 border-t-transparent rounded-full animate-spin shrink-0"></div>
                    <span className="text-orange-400 font-bold text-sm">
                      {lang === 'TR' ? 'İptal teklifiniz gönderildi. Karşı tarafın onayı bekleniyor...' : 'Cancel proposal sent. Awaiting counterparty approval...'}
                    </span>
                  </div>
                )}
                {cancelStatus === 'proposed_by_other' && (
                  <div>
                    <p className="text-orange-400 font-bold text-sm mb-2">⚠️ {lang === 'TR' ? 'Karşı taraf iptal teklif etti.' : 'Opponent proposed cancellation.'}</p>
                    <p className="text-[11px] text-slate-400 mb-3">
                      {tradeState === 'LOCKED'
                        ? (lang === 'TR' ? 'İşlem LOCKED aşamasında olduğu için herhangi bir kesinti yapılmayacaktır.' : 'Since trade is in LOCKED state, no fees will be deducted.')
                        : (lang === 'TR' ? 'Onaylarsanız standart protokol ücreti kesilecek ve kalan fonlar iade edilecektir.' : 'If you approve, standard protocol fee will be deducted and remaining funds returned.')}
                    </p>
                    <div className="grid grid-cols-2 gap-3">
                      <button onClick={handleProposeCancel} disabled={isContractLoading} className="w-full bg-orange-600 hover:bg-orange-500 text-white p-3 rounded-xl font-bold text-sm transition">
                        {isContractLoading ? '...' : (lang === 'TR' ? 'Onayla ve İptal Et' : 'Approve Cancel')}
                      </button>
                      <button onClick={() => setCancelStatus(null)} className="w-full bg-[#1a1a1f] border border-[#2a2a2e] hover:bg-[#222] text-white p-3 rounded-xl font-bold text-sm transition">
                        {lang === 'TR' ? 'Reddet' : 'Reject'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* PII bölümü: taker şifreli banka bilgilerini görür, maker ödeme beklediğini bilir */}
            {isTaker && tradeState !== 'RESOLVED' && (
              <div className="border border-[#222] rounded-xl overflow-hidden mt-6 bg-[#0a0a0c] p-1">
                <PIIDisplay tradeId={activeTrade?.id} lang={lang} getSafeTelegramUrl={getSafeTelegramUrl} />
              </div>
            )}
            {isMaker && tradeState !== 'RESOLVED' && (
              <div className="bg-[#0a0a0c] p-6 rounded-xl border border-[#222] text-center mt-6">
                <div className="text-3xl mb-2">🏦</div>
                <p className="text-slate-300 font-medium text-sm">{lang === 'TR' ? 'Banka hesabınıza ödeme bekleniyor.' : 'Waiting for fiat payment.'}</p>
                <p className="text-xs text-slate-500 mt-2">{lang === 'TR' ? 'Alıcı IBAN ve Telegram bilgilerinizi şifreli kanaldan aldı.' : 'Buyer received your IBAN & Telegram via encrypted channel.'}</p>
              </div>
            )}

            {/* burnExpired butonu — CHALLENGED ve 10 günü geçmiş işlemler için */}
            {activeTrade?.onchainId && tradeState === 'CHALLENGED' && (() => {
              const burnDate = activeTrade.challengedAt;
              if (!burnDate) return null;
              const isExpired = new Date().getTime() - new Date(burnDate).getTime() > 10 * 24 * 3600 * 1000;
              if (!isExpired) return null;
              return (
                <div className="mt-6 bg-[#1a0505] border border-red-950 rounded-xl p-4 text-center">
                  <p className="text-red-500 text-xs font-bold mb-2">
                    🔥 {lang === 'TR' ? '10 Gün Süresi Doldu — Sözleşme Artık Yakılabilir' : '10-Day Deadline Passed — Contract Can Now Be Burned'}
                  </p>
                  <p className="text-slate-500 text-[11px] mb-3">
                    {lang === 'TR' ? 'Uyarı: Sözleşme yakıldığında içerideki kilitli tüm USDT ve her iki tarafın teminatları kalıcı olarak Protokol Hazinesine aktarılır. İade yapılmaz.' : 'Warning: When burned, all locked USDT and bonds from both parties are permanently transferred to the Treasury. No refunds.'}
                  </p>
                  <button
                    onClick={async () => {
                      if (isContractLoading) return;
                      try {
                        setIsContractLoading(true);
                        showToast(lang === 'TR' ? 'Yakma işlemi gönderiliyor... Cüzdanınızdan onaylayın.' : 'Burn transaction sent... Confirm in wallet.', 'info');
                        await burnExpired(BigInt(activeTrade.onchainId));
                        setTradeState('RESOLVED');
                        setCurrentView('home');
                        showToast(lang === 'TR' ? '🔥 İşlem yakıldı. Maker bond protokole aktarıldı.' : '🔥 Trade burned. Maker bond transferred to protocol.', 'success');
                      } catch (err) {
                        console.error('burnExpired error:', err);
                        const reason = err.reason || err.message || (lang === 'TR' ? 'Yakma işlemi başarısız.' : 'Burn failed.');
                        showToast(reason, 'error');
                      } finally {
                        setIsContractLoading(false);
                      }
                    }}
                    disabled={isContractLoading}
                    className={`px-6 py-2.5 rounded-xl font-bold text-sm transition ${isContractLoading ? 'bg-[#1a1a1f] text-slate-500 cursor-not-allowed border border-[#2a2a2e]' : 'bg-red-900/30 text-red-400 border border-red-800/50 hover:bg-red-600 hover:text-white'}`}>
                    {isContractLoading ? '⏳...' : (lang === 'TR' ? '🔥 Süresi Dolan İşlemi Yak' : '🔥 Burn Expired Trade')}
                  </button>
                </div>
              );
            })()}
          </div>
        </div>
      </div>
    );
  };

  // [TR] Mobil alt navigasyon çubuğu — yalnızca mobil cihazlarda görünür
  // [EN] Mobile bottom navigation bar — visible only on mobile devices
  const renderMobileNav = () => (
    <div className="md:hidden fixed bottom-0 left-0 right-0 h-16 bg-[#060608] border-t border-[#1a1a1a] z-[45] flex items-center justify-around px-2 pb-safe shadow-[0_-10px_30px_rgba(0,0,0,0.5)]">
      <button onClick={() => setCurrentView('home')} className={`p-2 text-xl transition-all ${currentView === 'home' ? 'text-white drop-shadow-[0_0_8px_rgba(255,255,255,0.5)] -translate-y-1' : 'text-slate-600'}`}>🏠</button>
      <button onClick={() => setCurrentView('market')} className={`p-2 text-xl transition-all ${currentView === 'market' ? 'text-white drop-shadow-[0_0_8px_rgba(255,255,255,0.5)] -translate-y-1' : 'text-slate-600'}`}>🛒</button>
      <button onClick={() => setCurrentView('tradeRoom')} className={`p-2 text-xl transition-all relative ${currentView === 'tradeRoom' ? 'text-orange-500 drop-shadow-[0_0_8px_rgba(249,115,22,0.5)] -translate-y-1' : 'text-slate-600'}`}>
        💼{activeEscrows.length > 0 && <span className="absolute top-2 right-1 w-2.5 h-2.5 bg-orange-500 border border-[#060608] rounded-full animate-pulse"></span>}
      </button>
      <button onClick={openSidebar} className={`p-2 text-xl transition-all ${sidebarOpen ? 'text-white -translate-y-1' : 'text-slate-600'}`}>☰</button>
      <button onClick={handleAuthAction} className={`p-2 text-xl transition-all ${isConnected && isAuthenticated ? 'text-emerald-500 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)] -translate-y-1' : 'text-slate-600'}`}>
        {isConnected && isAuthenticated ? '👤' : '👛'}
      </button>
    </div>
  );

  // [TR] Kullanım koşulları modalı — ilk bağlantıda bir kez gösterilir, localStorage'a kaydedilir
  // [EN] Terms of use modal — shown once on first connect, persisted to localStorage
  const renderTermsModal = () => {
    if (termsAccepted || (!isConnected && !isAuthenticated)) return null;
    return (
      <div className="fixed inset-0 bg-[#060608]/95 backdrop-blur-xl flex items-center justify-center p-4 z-[200]">
        <div className="bg-[#111113] border border-[#222] rounded-2xl p-6 w-full max-w-lg shadow-2xl flex flex-col">
          <h2 className="text-xl font-bold text-white mb-4">📜 {lang === 'TR' ? 'Platform Kullanım Sözleşmesi ve Sorumluluk Reddi' : 'Terms of Use and Disclaimer'}</h2>
          <div className="space-y-4 text-sm text-slate-400 mb-6 bg-[#0a0a0c] p-4 rounded-xl border border-[#222] overflow-y-auto max-h-64">
            <p>{lang === 'TR' ? 'Araf Protokolü merkeziyetsiz bir akıllı kontrattır. Hiçbir aracı kurum veya hakem bulunmamaktadır.' : 'Araf Protocol is a decentralized smart contract. There are no intermediaries or arbitrators.'}</p>
            <p>{lang === 'TR' ? 'Tüm işlemleriniz kendi sorumluluğunuzdadır. "Bleeding Escrow" (Eriyen Kasa) oyun teorisine dayalı çalışır ve itiraz durumlarında fonlarınız zamanla eriyebilir.' : 'All transactions are at your own risk. The system operates on the "Bleeding Escrow" game theory, and in case of disputes, your funds may decay over time.'}</p>
            <p className="text-red-400 font-bold">{lang === 'TR' ? 'Chargeback (Ters İbraz) riski tamamen Maker (Satıcı) tarafına aittir. Gelen fonların kaynağını doğrulamak sizin sorumluluğunuzdadır.' : 'The risk of Chargeback belongs entirely to the Maker (Seller). It is your responsibility to verify the source of incoming funds.'}</p>
          </div>
          <button
            onClick={() => { localStorage.setItem('araf_terms_accepted', 'true'); setTermsAccepted(true); }}
            className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl transition shadow-[0_0_15px_rgba(16,185,129,0.3)]"
          >
            {lang === 'TR' ? 'Okudum, Kabul Ediyorum' : 'I Read and Accept'}
          </button>
        </div>
      </div>
    );
  };

  // ═══════════════════════════════════════════
  // 13. ANA RENDER
  //     Root layout: rail + sidebar + content + modals + toast
  // ═══════════════════════════════════════════
  return (
    <div className="flex flex-col md:flex-row h-screen bg-[#060608] text-slate-100 font-sans overflow-hidden selection:bg-emerald-500/30 pb-16 md:pb-0 relative">
      <EnvWarningBanner />

      {isPaused && (
        <div className="absolute top-0 left-0 right-0 z-[70] bg-red-950/90 backdrop-blur border-b border-red-800 px-6 py-2 flex justify-center items-center shadow-xl">
          <span className="text-sm font-bold text-red-200">⚠️ {lang === 'TR' ? 'Sistem şu an bakım modundadır. Yeni işlem açılamaz.' : 'System is currently in maintenance mode. New trades cannot be opened.'}</span>
        </div>
      )}

      {isConnected && ![8453, 84532, 31337].includes(chainId) && (
        <div className="absolute top-0 left-0 right-0 z-[80] bg-red-950/95 backdrop-blur border-b border-red-800 px-6 py-2 flex justify-center items-center shadow-xl">
          <span className="text-sm font-bold text-red-200">⚠️ {lang === 'TR' ? 'Yanlış Ağ! Lütfen cüzdanınızdan Base Sepolia ağına geçin.' : 'Wrong Network! Please switch to Base Sepolia in your wallet.'}</span>
        </div>
      )}

      {isConnected && isWalletRegistered === false && (
        <div className="absolute top-0 left-0 right-0 z-[60] bg-orange-900/90 backdrop-blur border-b border-orange-700 px-6 py-2 flex justify-center items-center gap-4 shadow-xl">
          <span className="text-sm font-bold text-orange-200">⚠️ {lang === 'TR' ? 'Cüzdan On-Chain Kayıtlı Değil (Anti-Sybil 7 Gün)' : 'Wallet Not Registered (Anti-Sybil 7 Days)'}</span>
          <button onClick={handleRegisterWallet} disabled={isRegisteringWallet} className="bg-orange-500 text-black px-4 py-1.5 rounded-lg text-xs font-bold hover:bg-orange-400 disabled:opacity-50 transition">{isRegisteringWallet ? '⏳' : '📝 Kaydet'}</button>
        </div>
      )}

      {renderSlimRail()}
      {renderContextSidebar()}
      {renderMobileNav()}

      <div className="flex-1 overflow-y-auto relative bg-[#060608]">
        <div className="min-h-full flex flex-col pt-4 md:pt-10 pb-24 md:pb-10 items-center">
          {currentView === 'home' ? renderHome() : currentView === 'market' ? renderMarket() : renderTradeRoom()}
        </div>
      </div>

      {renderWalletModal()}
      {renderFeedbackModal()}
      {renderMakerModal()}
      {renderProfileModal()}
      {renderTermsModal()}

      <button
        onClick={() => setShowFeedbackModal(true)}
        title={lang === 'TR' ? 'Geri Bildirim' : 'Feedback'}
        className="fixed bottom-20 md:bottom-6 left-6 z-40 w-12 h-12 bg-[#111113] hover:bg-[#1a1a1f] border border-[#222] rounded-full flex items-center justify-center text-xl shadow-[0_0_15px_rgba(0,0,0,0.5)] transition-transform hover:scale-105 hover:border-slate-600"
      >
        💬
      </button>

      {toast && (
        <div className="fixed bottom-20 md:bottom-6 left-1/2 -translate-x-1/2 md:left-auto md:-translate-x-0 md:right-6 z-[100] animate-bounce-in w-[90%] sm:w-auto">
          <div className={`px-4 md:px-6 py-3 md:py-4 rounded-xl shadow-2xl border text-sm font-bold backdrop-blur-md text-center md:text-left ${toast.type === 'error' ? 'bg-[#1a0f0f]/90 border-red-900/50 text-red-400' : toast.type === 'info' ? 'bg-[#0a1a2a]/90 border-blue-900/50 text-blue-400' : 'bg-[#0a1a10]/90 border-emerald-900/50 text-emerald-400'}`}>
            {toast.message}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
