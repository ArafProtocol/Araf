import { useState, useEffect, useRef } from 'react';

/**
 * useCountdown — Hedef tarihe kadar olan süreyi hesaplayan React hook'u.
 *
 * YÜKS-08 Fix: Başlangıç state'i artık targetDate'e göre hesaplanıyor.
 *   ÖNCEKİ: isFinished varsayılan olarak `true` geliyordu.
 *   Sorun: Sayfa yenilendiğinde "Release" ve "Challenge" gibi kritik butonlar
 *   bir anlık aktif görünüp kapanıyordu. Kullanıcı bu milisaniyede basarsa
 *   kontrat hata veriyordu.
 *   ŞİMDİ: targetDate null veya geçmişse isFinished=true, değilse isFinished=false.
 *
 * YÜKS-19 Fix: Arka plan sekme kısıtlamasına (Background Throttling) karşı
 *   Page Visibility API ile senkronizasyon eklendi.
 *   ÖNCEKİ: setInterval(1000) — tarayıcı sekme arka planda olduğunda
 *   bu interval'ı yavaşlatır veya durdurur. 48/240 saatlik uzun süreçlerde
 *   UI'daki sayaç on-chain zamandan 15-20 dakika geri kalabiliyordu.
 *   ŞİMDİ: Sekme ön plana geldiğinde anlık hesaplama yapılır ve sayaç
 *   gerçek zamana senkronize edilir.
 *
 * @param {Date | string | null} targetDate - Geri sayımın yapılacağı hedef tarih.
 * @returns {{days: number, hours: number, minutes: number, seconds: number, isFinished: boolean}}
 */
export function useCountdown(targetDate) {
  // [TR] Başlangıç değerini targetDate'e göre hesapla — flicker'ı önler
  // [EN] Calculate initial value from targetDate — prevents initial flicker
  const getInitialState = (target) => {
    if (!target) {
      return { days: 0, hours: 0, minutes: 0, seconds: 0, isFinished: true };
    }
    const distance = new Date(target).getTime() - Date.now();
    if (distance <= 0) {
      return { days: 0, hours: 0, minutes: 0, seconds: 0, isFinished: true };
    }
    return {
      days:       Math.floor(distance / (1000 * 60 * 60 * 24)),
      hours:      Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)),
      minutes:    Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60)),
      seconds:    Math.floor((distance % (1000 * 60)) / 1000),
      isFinished: false,
    };
  };

  const [timeLeft, setTimeLeft] = useState(() => getInitialState(targetDate));
  const intervalRef = useRef(null);

  // [TR] Her tick'te kalan süreyi hesapla
  // [EN] Calculate remaining time on each tick
  const calculateTimeLeft = (target) => {
    if (!target) return { days: 0, hours: 0, minutes: 0, seconds: 0, isFinished: true };

    const distance = new Date(target).getTime() - Date.now();

    if (distance <= 0) {
      return { days: 0, hours: 0, minutes: 0, seconds: 0, isFinished: true };
    }

    return {
      days:       Math.floor(distance / (1000 * 60 * 60 * 24)),
      hours:      Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)),
      minutes:    Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60)),
      seconds:    Math.floor((distance % (1000 * 60)) / 1000),
      isFinished: false,
    };
  };

  useEffect(() => {
    // [TR] targetDate değiştiğinde başlangıç state'ini hemen güncelle — flicker yok
    // [EN] Immediately update state when targetDate changes — no flicker
    setTimeLeft(getInitialState(targetDate));

    if (!targetDate) return;

    const targetTime = new Date(targetDate).getTime();
    if (targetTime <= Date.now()) return;

    // [TR] Her saniye güncelle
    // [EN] Update every second
    intervalRef.current = setInterval(() => {
      const state = calculateTimeLeft(targetDate);
      setTimeLeft(state);
      if (state.isFinished && intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    }, 1000);

    // YÜKS-19 Fix: Page Visibility API — sekme ön plana gelince sayacı senkronize et
    // Arka planda bekleyen interval'ın biriktirdiği sapmayı düzeltir.
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        setTimeLeft(calculateTimeLeft(targetDate));
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetDate]);

  return timeLeft;
}
