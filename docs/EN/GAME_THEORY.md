# 🌀 Araf Protocol: Game Theory Visualized

This document visually explains the core game theory and resolution paths of the Araf Protocol using a state-flow diagram.

---

## Bleeding Escrow Flowchart

This diagram illustrates all possible paths an escrow can take once a Taker reports a payment (`PAID` state) — including the happy path, auto-release mechanism, and the multi-phased dispute resolution (Purgatory).

> **Security note:** A `ConflictingPingPath` guard prevents both ping paths from being open simultaneously. If the Maker calls `pingTakerForChallenge`, the Taker cannot call `pingMaker` (autoRelease path), and vice versa. This prevents MEV and transaction ordering manipulation.

```mermaid
flowchart TD
    %% Styling Classes
    classDef state fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b
    classDef success fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    classDef warning fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#e65100
    classDef danger fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#b71c1c
    classDef action fill:#ffffff,stroke:#9e9e9e,stroke-width:1px
    classDef phase fill:#f3e5f5,stroke:#8e24aa,stroke-width:2px,stroke-dasharray: 4

    %% Define Nodes
    PAID(["🔵 STATE: PAID<br>(Taker reports payment)"])
    ActionRelease["Maker: releaseFunds()"]
    ResOk(("✅ RESOLVED<br>(Normal)"))

    ActionPingMaker["Taker: pingMaker()"]
    ActionAuto["Taker: autoRelease()"]
    ResPen(("⚠️ RESOLVED<br>(2% Penalty)"))

    ActionPingTaker["Maker: pingTakerForChallenge()"]
    ActionChallenge["Maker: challengeTrade()"]
    CHALLENGED(["🔴 STATE: CHALLENGED<br>(Dispute Opened)"])

    %% Define Connections
    PAID -->|"Happy Path"| ActionRelease
    ActionRelease --> ResOk

    PAID -->|"Maker Inactive<br>(Waits 48h)"| ActionPingMaker
    ActionPingMaker -->|"No response<br>(Waits 24h)"| ActionAuto
    ActionAuto --> ResPen

    PAID -->|"Payment Missing<br>(Waits 24h)"| ActionPingTaker
    ActionPingTaker -->|"No resolution<br>(Waits 24h)"| ActionChallenge
    ActionChallenge --> CHALLENGED

    %% Purgatory Subgraph
    subgraph Purgatory [Dispute Resolution Phases - Purgatory]
        direction TB
        GRACE["🛡️ 48h Grace Period<br>(No Fund Decay)"]
        CANCELED(("🔄 CANCELED<br>(Refunds Issued)"))
        BLEEDING["🩸 10-Day Bleeding Phase<br>(Hourly Decay Starts)"]
        ActionBurn["Any: burnExpired()"]
        BURNED(("💀 BURNED<br>(Funds to Treasury)"))

        CHALLENGED --> GRACE
        GRACE -->|"Mutual Agreement<br>(EIP-712)"| CANCELED
        GRACE -->|"No Agreement<br>(After 48h)"| BLEEDING
        BLEEDING -->|"Mutual Agreement"| CANCELED
        BLEEDING -->|"No Agreement<br>(After 10 Days)"| ActionBurn
        ActionBurn --> BURNED
    end

    %% Apply Classes Safely
    class PAID,CHALLENGED state;
    class ResOk success;
    class ResPen warning;
    class CANCELED action;
    class ActionRelease,ActionPingMaker,ActionAuto,ActionPingTaker,ActionChallenge,ActionBurn action;
    class GRACE phase;
    class BLEEDING,BURNED danger;
```
