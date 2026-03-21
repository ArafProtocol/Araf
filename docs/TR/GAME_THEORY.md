# 🌀 Araf Protocol: Oyun Teorisi Görselleştirmesi

Bu doküman, Araf Protokolü'nün temel oyun teorisini ve çözümleme yollarını bir durum-akış diyagramı (state-flow diagram) kullanarak görsel olarak açıklar.

---

## Bleeding Escrow Akış Şeması

Bu diyagram, bir Taker'ın ödeme bildiriminde bulunmasının ardından (`PAID` durumu) bir escrow'un izleyebileceği tüm olası yolları gösterir — buna sorunsuz yol (happy path), otomatik serbest bırakma mekanizması (auto-release) ve çok aşamalı anlaşmazlık çözümü (Purgatory - Araf) dahildir.

> **Güvenlik notu:** `ConflictingPingPath` koruması, her iki "ping" yolunun aynı anda açık olmasını engeller. Eğer Maker `pingTakerForChallenge` çağırırsa, Taker `pingMaker` (autoRelease yolu) çağıramaz veya tam tersi. Bu durum, MEV ve işlem sırası manipülasyonunu (transaction ordering manipulation) önler.

```mermaid
flowchart TD
    %% Stil Sınıfları
    classDef state fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b
    classDef success fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    classDef warning fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#e65100
    classDef danger fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#b71c1c
    classDef action fill:#ffffff,stroke:#9e9e9e,stroke-width:1px
    classDef phase fill:#f3e5f5,stroke:#8e24aa,stroke-width:2px,stroke-dasharray: 4

    %% Düğümleri (Nodes) Tanımla
    PAID(["🔵 DURUM: ÖDENDİ (PAID)<br>(Taker ödemeyi bildirir)"])
    ActionRelease["Maker: Fonları Serbest Bırakır (releaseFunds)"]
    ResOk(("✅ ÇÖZÜLDÜ (RESOLVED)<br>(Normal)"))

    ActionPingMaker["Taker: Maker'ı Dürt (pingMaker)"]
    ActionAuto["Taker: Otomatik Serbest Bırak (autoRelease)"]
    ResPen(("⚠️ ÇÖZÜLDÜ (RESOLVED)<br>(%2 Ceza)"))

    ActionPingTaker["Maker: İtiraz İçin Taker'ı Dürt<br>(pingTakerForChallenge)"]
    ActionChallenge["Maker: İşleme İtiraz Et (challengeTrade)"]
    CHALLENGED(["🔴 DURUM: İTİRAZ EDİLDİ (CHALLENGED)<br>(Anlaşmazlık Açıldı)"])

    %% Bağlantıları Tanımla
    PAID -->|"Sorunsuz Yol"| ActionRelease
    ActionRelease --> ResOk

    PAID -->|"Maker İnaktif<br>(48s Bekler)"| ActionPingMaker
    ActionPingMaker -->|"Yanıt Yok<br>(24s Bekler)"| ActionAuto
    ActionAuto --> ResPen

    PAID -->|"Ödeme Eksik<br>(24s Bekler)"| ActionPingTaker
    ActionPingTaker -->|"Çözüm Yok<br>(24s Bekler)"| ActionChallenge
    ActionChallenge --> CHALLENGED

    %% Purgatory (Araf) Alt Grafiği
    subgraph Purgatory [Anlaşmazlık Çözüm Aşamaları - Araf]
        direction TB
        GRACE["🛡️ 48s Mühlet Süresi<br>(Fon Kaybı Yok)"]
        CANCELED(("🔄 İPTAL EDİLDİ (CANCELED)<br>(İadeler Yapıldı)"))
        BLEEDING["🩸 10 Günlük Kanamalı Aşama<br>(Saatlik Kayıp Başlar)"]
        ActionBurn["Herhangi Biri: Süresi Dolanları Yak (burnExpired)"]
        BURNED(("💀 YAKILDI (BURNED)<br>(Fonlar Hazineye)"))

        CHALLENGED --> GRACE
        GRACE -->|"Karşılıklı Anlaşma<br>(EIP-712)"| CANCELED
        GRACE -->|"Anlaşma Yok<br>(48s Sonra)"| BLEEDING
        BLEEDING -->|"Karşılıklı Anlaşma"| CANCELED
        BLEEDING -->|"Anlaşma Yok<br>(10 Gün Sonra)"| ActionBurn
        ActionBurn --> BURNED
    end

    %% Sınıfları Güvenli Bir Şekilde Uygula
    class PAID,CHALLENGED state;
    class ResOk success;
    class ResPen warning;
    class CANCELED action;
    class ActionRelease,ActionPingMaker,ActionAuto,ActionPingTaker,ActionChallenge,ActionBurn action;
    class GRACE phase;
    class BLEEDING,BURNED danger;
```
