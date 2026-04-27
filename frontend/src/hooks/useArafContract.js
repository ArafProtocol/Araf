import { useCallback } from 'react'
import { usePublicClient, useWalletClient, useChainId } from 'wagmi'
import { parseAbi, getAddress } from 'viem'

const ArafEscrowABI = parseAbi([
  'function registerWallet()',
  'function createEscrow(address _token, uint256 _cryptoAmount, uint8 _tier, bytes32 _listingRef)',
  'function cancelOpenEscrow(uint256 _tradeId)',
  'function lockEscrow(uint256 _tradeId)',
  'function reportPayment(uint256 _tradeId, string calldata _ipfsHash)',
  'function releaseFunds(uint256 _tradeId)',
  'function challengeTrade(uint256 _tradeId)',
  'function autoRelease(uint256 _tradeId)',
  'function burnExpired(uint256 _tradeId)',
  'function proposeOrApproveCancel(uint256 _tradeId, uint256 _deadline, bytes calldata _sig)',
  'function pingMaker(uint256 _tradeId)',
  'function pingTakerForChallenge(uint256 _tradeId)',
  'function decayReputation(address _wallet)',
  'function getReputation(address _wallet) view returns (uint256 successful, uint256 failed, uint256 bannedUntil, uint256 consecutiveBans, uint8 effectiveTier)',
  'function antiSybilCheck(address _wallet) view returns (bool aged, bool funded, bool cooldownOk)',
  'function getCooldownRemaining(address _wallet) view returns (uint256)',
  'function walletRegisteredAt(address _wallet) view returns (uint256)',
  'function TAKER_FEE_BPS() view returns (uint256)',
  'function getFirstSuccessfulTradeAt(address _wallet) view returns (uint256)',
  'function getTrade(uint256 _tradeId) view returns ((uint256 id, address maker, address taker, address tokenAddress, uint256 cryptoAmount, uint256 makerBond, uint256 takerBond, uint8 tier, uint8 state, uint256 lockedAt, uint256 paidAt, uint256 challengedAt, string ipfsReceiptHash, bool cancelProposedByMaker, bool cancelProposedByTaker, uint256 pingedAt, bool pingedByTaker, uint256 challengePingedAt, bool challengePingedByMaker))',
  'function sigNonces(address) view returns (uint256)',
  'function domainSeparator() view returns (bytes32)',
  'function getCurrentAmounts(uint256 _tradeId) view returns (uint256 cryptoRemaining, uint256 makerBondRemaining, uint256 takerBondRemaining, uint256 totalDecayed)',
  'function paused() view returns (bool)',
])

const ERC20_ABI = parseAbi([
  'function approve(address spender, uint256 amount) returns (bool)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function decimals() view returns (uint8)',
])

const ESCROW_ADDRESS = import.meta.env.VITE_ESCROW_ADDRESS
const USDC_ADDRESS = import.meta.env.VITE_USDC_ADDRESS
const isValidEscrowAddress =
  Boolean(ESCROW_ADDRESS) &&
  ESCROW_ADDRESS !== '0x0000000000000000000000000000000000000000'

const CHAIN_LABELS = {
  8453: 'Base Mainnet',
  84532: 'Base Sepolia',
  31337: 'Hardhat Local',
}

const BASE_SEPOLIA_CHAIN_ID = 84532
const DEFAULT_USDC_FAUCET_URL = 'https://faucet.circle.com/'

const getTestnetUsdcFaucetUrl = () =>
  import.meta.env.VITE_TESTNET_USDC_FAUCET_URL || DEFAULT_USDC_FAUCET_URL

const isSameAddress = (left, right) => {
  if (!left || !right) return false
  try {
    return getAddress(left) === getAddress(right)
  } catch {
    return false
  }
}

// [TR] Production'da tek chain, development'ta çoklu chain desteği.
// [EN] Single-chain in production, multi-chain support in development.
const getSupportedChainLabels = () => {
  if (import.meta.env.PROD) {
    const id = Number(import.meta.env.VITE_ALLOWED_CHAIN_ID || 84532)
    return { [id]: CHAIN_LABELS[id] || `Chain ${id}` }
  }
  return CHAIN_LABELS
}

const getSupportedChainNamesText = () => Object.values(getSupportedChainLabels()).join(' veya ')

export function useArafContract() {
  const publicClient = usePublicClient()
  const { data: walletClient } = useWalletClient()
  const chainId = useChainId()

  const validateChain = useCallback(() => {
    const supportedChains = getSupportedChainLabels()
    if (!supportedChains[chainId]) {
      const supportedNames = getSupportedChainNamesText()
      throw new Error(
        `Yanlış ağ! Cüzdanınız şu an Chain ID ${chainId} üzerinde. ` +
        `Araf Protocol bu ortamda yalnız ${supportedNames} üzerinde çalışır.`
      )
    }
  }, [chainId])

  const writeContract = useCallback(
    async (functionName, args = []) => {
      if (!walletClient) {
        throw new Error('İşlem için aktif wallet client bulunamadı. Cüzdan bağlantınızı ve oturum imzanızı kontrol edin.')
      }
      if (!isValidEscrowAddress) {
        throw new Error('Kontrat adresi yapılandırılmamış. VITE_ESCROW_ADDRESS geçerli bir adres olmalı.')
      }

      validateChain()

      try {
        const hash = await walletClient.writeContract({
          address: getAddress(ESCROW_ADDRESS),
          abi: ArafEscrowABI,
          functionName,
          args,
        })

        if (typeof window !== 'undefined') {
          localStorage.setItem(
            'araf_pending_tx',
            JSON.stringify({
              hash,
              functionName,
              createdAt: Date.now(),
              chainId,
              escrow: getAddress(ESCROW_ADDRESS),
            }),
          )
        }

        const receipt = await publicClient.waitForTransactionReceipt({ hash })
        if (typeof window !== 'undefined') {
          localStorage.removeItem('araf_pending_tx')
        }
        return receipt
      } catch (error) {
        const errorMessage = error.shortMessage || error.reason || error.message || 'Bilinmeyen kontrat hatası'
        const apiUrl = import.meta.env.VITE_API_URL || '/api'

        fetch(`${apiUrl}/logs/client-error`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            level: 'ERROR',
            message: `[CONTRACT-REVERT] ${functionName}: ${errorMessage}`,
            url: typeof window !== 'undefined' ? window.location.href : '',
            wallet: walletClient?.account?.address,
          }),
        }).catch(() => {})

        throw error
      }
    },
    [walletClient, publicClient, validateChain, chainId],
  )

  const registerWallet = useCallback(() => writeContract('registerWallet'), [writeContract])
  const createEscrow = useCallback((token, cryptoAmount, tier, listingRef) => writeContract('createEscrow', [token, cryptoAmount, tier, listingRef]), [writeContract])
  const cancelOpenEscrow = useCallback((tradeId) => writeContract('cancelOpenEscrow', [tradeId]), [writeContract])
  const lockEscrow = useCallback((tradeId) => writeContract('lockEscrow', [tradeId]), [writeContract])
  const reportPayment = useCallback((tradeId, ipfsHash) => writeContract('reportPayment', [tradeId, ipfsHash]), [writeContract])
  const releaseFunds = useCallback((tradeId) => writeContract('releaseFunds', [tradeId]), [writeContract])
  const challengeTrade = useCallback((tradeId) => writeContract('challengeTrade', [tradeId]), [writeContract])
  const autoRelease = useCallback((tradeId) => writeContract('autoRelease', [tradeId]), [writeContract])
  const burnExpired = useCallback((tradeId) => writeContract('burnExpired', [tradeId]), [writeContract])
  const pingMaker = useCallback((tradeId) => writeContract('pingMaker', [tradeId]), [writeContract])
  const pingTakerForChallenge = useCallback((tradeId) => writeContract('pingTakerForChallenge', [tradeId]), [writeContract])
  const decayReputation = useCallback((wallet) => writeContract('decayReputation', [wallet]), [writeContract])

  const approveToken = useCallback(
    async (tokenAddress, amount) => {
      if (!walletClient) {
        throw new Error('İşlem için aktif wallet client bulunamadı. Cüzdan bağlantınızı ve oturum imzanızı kontrol edin.')
      }
      if (!isValidEscrowAddress) {
        throw new Error('VITE_ESCROW_ADDRESS tanımlı değil.')
      }

      validateChain()

      const hash = await walletClient.writeContract({
        address: getAddress(tokenAddress),
        abi: ERC20_ABI,
        functionName: 'approve',
        args: [getAddress(ESCROW_ADDRESS), amount],
      })
      return publicClient.waitForTransactionReceipt({ hash })
    },
    [walletClient, publicClient, validateChain],
  )

  const mintToken = useCallback(
    async (tokenAddress) => {
      validateChain()

      // [TR] Base Sepolia'da yalnız resmi USDC butonu Circle faucet'e yönlenir.
      //      Mock USDT aynı ağda kendi MockERC20 mint() fonksiyonunu çağırmaya devam eder.
      // [EN] On Base Sepolia, only the official USDC button redirects to Circle faucet.
      //      Mock USDT keeps calling its own MockERC20 mint() function on the same network.
      if (chainId === BASE_SEPOLIA_CHAIN_ID && isSameAddress(tokenAddress, USDC_ADDRESS)) {
        const faucetUrl = getTestnetUsdcFaucetUrl()

        if (typeof window === 'undefined') {
          throw new Error(`Base Sepolia USDC faucet bağlantısı: ${faucetUrl}`)
        }

        const opened = window.open(faucetUrl, '_blank', 'noopener,noreferrer')
        if (!opened) {
          window.location.assign(faucetUrl)
        }

        return { redirected: true, faucetUrl }
      }

      if (!walletClient) {
        throw new Error('İşlem için aktif wallet client bulunamadı. Cüzdan bağlantınızı ve oturum imzanızı kontrol edin.')
      }

      const hash = await walletClient.writeContract({
        address: getAddress(tokenAddress),
        abi: parseAbi(['function mint()']),
        functionName: 'mint',
      })
      return publicClient.waitForTransactionReceipt({ hash })
    },
    [walletClient, publicClient, validateChain, chainId],
  )

  const getAllowance = useCallback(
    async (tokenAddress, ownerAddress) => {
      if (!isValidEscrowAddress) return 0n

      try {
        return await publicClient.readContract({
          address: getAddress(tokenAddress),
          abi: ERC20_ABI,
          functionName: 'allowance',
          args: [getAddress(ownerAddress), getAddress(ESCROW_ADDRESS)],
        })
      } catch {
        return 0n

      }
    },
    [publicClient],
  )

  const getTokenDecimals = useCallback(
    async (tokenAddress) => {
      try {
        const decimals = await publicClient.readContract({
          address: getAddress(tokenAddress),
          abi: ERC20_ABI,
          functionName: 'decimals',
        })
        return Number(decimals)
      } catch {
        return 6
      }
    },
    [publicClient],
  )

  const signCancelProposal = useCallback(
    async (tradeId, nonce, deadlineOverride) => {
      if (!walletClient) throw new Error('Cüzdan bağlı değil')

      validateChain()

      const now = Math.floor(Date.now() / 1000)
      const deadline = deadlineOverride || now + 3600
      const maxDeadline = now + 7 * 24 * 60 * 60

      if (deadline <= now) {
        throw new Error('Deadline geçmiş bir zamana ayarlanamaz.')
      }
      if (deadline > maxDeadline) {
        throw new Error('Deadline çok uzak. Maksimum 7 gün sonrası kabul edilir.')
      }

      const domain = {
        name: 'ArafEscrow',
        version: '1',
        chainId,
        verifyingContract: getAddress(ESCROW_ADDRESS),
      }

      const types = {
        CancelProposal: [
          { name: 'tradeId', type: 'uint256' },
          { name: 'proposer', type: 'address' },
          { name: 'nonce', type: 'uint256' },
          { name: 'deadline', type: 'uint256' },
        ],
      }

      const message = {
        tradeId: BigInt(tradeId),
        proposer: walletClient.account.address,
        nonce: BigInt(nonce),
        deadline: BigInt(deadline),
      }

      const signature = await walletClient.signTypedData({
        domain,
        types,
        primaryType: 'CancelProposal',
        message,
      })

      return { signature, deadline }
    },
    [walletClient, chainId, validateChain],
  )

  const proposeOrApproveCancel = useCallback(
    (tradeId, deadline, signature) => writeContract('proposeOrApproveCancel', [tradeId, BigInt(deadline), signature]),
    [writeContract],
  )

  const readContractSafe = useCallback(
    async (functionName, args = [], fallback = null) => {
      if (!isValidEscrowAddress) return fallback
      try {
        return await publicClient.readContract({
          address: getAddress(ESCROW_ADDRESS),
          abi: ArafEscrowABI,
          functionName,
          args,
        })
      } catch {
        return fallback
      }
    },
    [publicClient],
  )

  return {
    registerWallet,
    createEscrow,
    cancelOpenEscrow,
    lockEscrow,
    reportPayment,
    releaseFunds,
    challengeTrade,
    autoRelease,
    burnExpired,
    pingMaker,
    pingTakerForChallenge,
    decayReputation,
    signCancelProposal,
    proposeOrApproveCancel,
    mintToken,
    approveToken,
    getAllowance,
    getTokenDecimals,
    getCurrentAmounts: useCallback((tradeId) => readContractSafe('getCurrentAmounts', [BigInt(tradeId)], null), [readContractSafe]),
    getPaused: useCallback(() => readContractSafe('paused', [], null), [readContractSafe]),
    antiSybilCheck: useCallback((address) => readContractSafe('antiSybilCheck', [getAddress(address)], null), [readContractSafe]),
    getCooldownRemaining: useCallback((address) => readContractSafe('getCooldownRemaining', [getAddress(address)], 0n), [readContractSafe]),
    getWalletRegisteredAt: useCallback((address) => readContractSafe('walletRegisteredAt', [getAddress(address)], 0n), [readContractSafe]),
    getTakerFeeBps: useCallback(() => readContractSafe('TAKER_FEE_BPS', [], 10n), [readContractSafe]),
    getReputation: useCallback((address) => readContractSafe('getReputation', [getAddress(address)], null), [readContractSafe]),
    getFirstSuccessfulTradeAt: useCallback((address) => readContractSafe('getFirstSuccessfulTradeAt', [getAddress(address)], 0n), [readContractSafe]),
    getTrade: useCallback((tradeId) => readContractSafe('getTrade', [BigInt(tradeId)], null), [readContractSafe]),
  }
}
