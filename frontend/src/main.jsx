import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

import { WagmiProvider, createConfig, http } from 'wagmi'
import { base, baseSepolia, hardhat } from 'wagmi/chains'
import { coinbaseWallet, injected } from 'wagmi/connectors'
import { farcasterFrame } from "@farcaster/frame-wagmi-connector" // [Farcaster] Frame içi cüzdan eklentisi
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import ErrorBoundary from './components/ErrorBoundary.jsx'

// YÜKS-09 Fix: ErrorBoundary WagmiProvider + QueryClientProvider'ın IÇINE alındı.
//   ÖNCEKİ: ErrorBoundary tüm provider'ları sarmalıyordu. Bir connector (OKX, Coinbase)
//   render hatası verirse ErrorBoundary TÜM uygulamayı, WagmiProvider dahil kapatıyordu.
//   Kullanıcı kilitli Trade Room'a erişemez hale geliyordu.
//   ŞİMDİ: Provider altyapısı çalışmaya devam ederken sadece UI hataları yakalanıyor.

/**
 * Dinamik Codespaces RPC yardımcı fonksiyonu.
 *
 * FRONT-05 Not: Codespaces instance'ı "Public" olarak ayarlanmışsa bu tünel
 * adresi internetten erişilebilir hale gelir. Sadece geliştirme için kullanın.
 * Codespaces "Private" modda tutulması şiddetle tavsiye edilir.
 */
const getCodespacesRPC = (port) => {
  try {
    const host = window.location.hostname;
    if (host === 'localhost' || host === '127.0.0.1') return `http://127.0.0.1:${port}`;
    // [TR] Codespaces: 5173 portunu hedef porta çevir
    return `https://${host.replace('-5173', `-${port}`)}`;
  } catch (e) {
    return `http://127.0.0.1:${port}`;
  }
};

const config = createConfig({
  // [TR] Geliştirme modunda Hardhat başa alınıyor — MetaMask Base'e bağlanmasın
  // [EN] In dev mode, Hardhat first — prevents MetaMask from defaulting to Base
  chains: import.meta.env.PROD
    ? [base, baseSepolia]
    : [hardhat, baseSepolia, base],
  connectors: [
    farcasterFrame(), // [Farcaster] Warpcast içi yerel cüzdanı yakalar ve önceliklendirir
    injected(), // OKX Wallet ve diğer injected cüzdanlar
    coinbaseWallet({ appName: 'Araf Protocol' }),
    // [TR] WalletConnect geçici olarak kapalı (Reown 403 hatasını engellemek için)
    // walletConnect({ projectId: 'PROJE_ID_BURAYA' }),
  ],
  transports: {
    [base.id]:        http(),
    [baseSepolia.id]: http(),
    // [TR] Hardhat yerel ağı — FRONT-05: sadece development'ta aktif
    [hardhat.id]:     http(import.meta.env.PROD ? undefined : getCodespacesRPC(8545)),
  },
})

const queryClient = new QueryClient()

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    {/*
      YÜKS-09 Fix: WagmiProvider ve QueryClientProvider DIŞARIDA kalıyor.
      Bu sayede connector/provider hatası tüm uygulamayı kapatmıyor.
      Sadece App ve alt bileşenlerinin render hataları yakalanıyor.
    */}
    <WagmiProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <ErrorBoundary>
          <App />
        </ErrorBoundary>
      </QueryClientProvider>
    </WagmiProvider>
  </React.StrictMode>,
)
