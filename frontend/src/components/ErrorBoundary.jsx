/**
 * ErrorBoundary — Global Render Hata Sınırı & Senkronize Loglama
 * * [TR] React render hatalarını yakalar, kullanıcıya dostu bir arayüz gösterir
 * ve hatayı backend'deki merkezi log sistemine sessizce gönderir.
 * [EN] Catches React render errors, displays a fallback UI, and silently
 * sends the error to the centralized backend logging system.
 */

import React from 'react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    // [TR] Bir sonraki render'da fallback UI gösterilmesi için state'i günceller.
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    // Tarayıcı konsoluna detaylı hata bas (Geliştirme aşaması için)
    console.error('[ErrorBoundary] Kritik Render Hatası:', error, errorInfo);
    
    // VITE_API_URL ortam değişkeninin tanımlı olduğundan emin olun.
    // DÜZELTME: Fallback port 3001 yerine projenin kullandığı 4000 yapıldı.
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000/api';

    fetch(`${apiUrl}/logs/client-error`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        level: 'ERROR', // Backend'in ayırt edebilmesi için eklendi
        message: error.message || 'Bilinmeyen Render Hatası',
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        url: window.location.href,
        timestamp: new Date().toISOString()
      })
    }).catch((err) => {
      // [TR] Backend kapalıysa veya ağ hatası varsa uygulamayı çökertmemek için sessizce yutulur.
      console.warn('[ErrorBoundary] Log backend sunucusuna gönderilemedi.');
    });
  }

  render() {
    if (this.state.hasError) {
      // [TR] Hata durumunda kullanıcıya gösterilecek yedek (fallback) arayüz
      return (
        <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4 font-sans">
          <div className="bg-slate-800 border border-red-500/30 rounded-2xl p-8 max-w-md w-full text-center shadow-2xl">
            <div className="text-5xl mb-6">⚠️</div>
            <h2 className="text-white font-bold text-2xl mb-3">Sistemde Kesinti Oluştu</h2>
            <p className="text-slate-400 text-sm mb-8 leading-relaxed">
              İşleminiz sırasında teknik bir sorunla karşılaşıldı. 
              Hata detayları teknik ekibimize (Araf-Protocol Log) iletildi.
            </p>
            <div className="flex flex-col gap-3">
              <button
                onClick={() => window.location.reload()}
                className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 px-6 rounded-xl transition-all active:scale-95 shadow-lg shadow-blue-900/20"
              >
                Sayfayı Yenile
              </button>
              <button
                onClick={() => window.location.href = '/'}
                className="w-full bg-transparent border border-slate-600 hover:bg-slate-700 text-slate-300 py-2.5 px-6 rounded-xl transition-all"
              >
                Ana Sayfaya Dön
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
