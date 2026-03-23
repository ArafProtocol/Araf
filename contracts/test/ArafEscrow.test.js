const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { time, loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

/**
 * ArafEscrow — Full Test Suite (v2.0 compatible)
 */

describe("ArafEscrow", function () {

  // ── Constants ──────────────────────────────────────────────────────────────

  const USDT_DECIMALS = 6;
  const TRADE_AMOUNT  = ethers.parseUnits("1000", USDT_DECIMALS);  // Tier 2+ trades
  const TIER0_AMOUNT  = ethers.parseUnits("100",  USDT_DECIMALS);  // Tier 0 (contract limit: 150)
  const INITIAL_BAL   = ethers.parseUnits("50000", USDT_DECIMALS);
  const BASELINE_SUCCESS = 200n;

  // After 200 successful trades: good-rep discount applied (-100 BPS = -1%)
  //   Tier 2 base maker: 600 BPS → 500 BPS = 5% → 1000 × 5% = 50 USDT
  //   Tier 2 base taker: 800 BPS → 700 BPS = 7% → 1000 × 7% = 70 USDT
  const MAKER_BOND_T2 = ethers.parseUnits("50", USDT_DECIMALS);
  const TAKER_BOND_T2 = ethers.parseUnits("70", USDT_DECIMALS);
  const TOTAL_LOCK_T2 = TRADE_AMOUNT + MAKER_BOND_T2;  // 1050

  const TAKER_FEE_BPS = 10n;
  const MAKER_FEE_BPS = 10n;
  const BPS_DENOM     = 10000n;

  // Timing constants (matching contract)
  const SEVEN_DAYS   = 7  * 24 * 3600;
  const FORTY_EIGHT_H = 48 * 3600;  // GRACE_PERIOD — required before pingMaker
  const TWENTY_FOUR_H = 24 * 3600;  // Response window after pings
  const FOUR_HOURS   = 4  * 3600;   // TIER0/1 cooldown (NOT 24h)
  const ONE_HOUR     = 3600;
  const TEN_DAYS     = 10 * 24 * 3600;

  let escrow, mockUSDT;
  let owner, treasury, maker, taker, attacker, stranger;

  // ── Fixture ─────────────────────────────────────────────────────────────────

  async function deployAndSetupFixture() {
    const [owner, treasury, maker, taker, attacker, stranger] = await ethers.getSigners();

    const MockERC20  = await ethers.getContractFactory("MockERC20");
    const mockUSDT   = await MockERC20.deploy("Mock USDT", "USDT", USDT_DECIMALS);

    const ArafEscrow = await ethers.getContractFactory("ArafEscrow");
    const escrow     = await ArafEscrow.deploy(treasury.address);

    const tokenAddr  = await mockUSDT.getAddress();
    const escrowAddr = await escrow.getAddress();

    await escrow.connect(owner).setSupportedToken(tokenAddr, true);

    // now available on MockERC20
    await mockUSDT.mint(maker.address,    INITIAL_BAL);
    await mockUSDT.mint(taker.address,    INITIAL_BAL);
    await mockUSDT.mint(attacker.address, INITIAL_BAL);

    await mockUSDT.connect(maker).approve(escrowAddr,    ethers.MaxUint256);
    await mockUSDT.connect(taker).approve(escrowAddr,    ethers.MaxUint256);
    await mockUSDT.connect(attacker).approve(escrowAddr, ethers.MaxUint256);

    // Register wallets and wait 7-day aging period
    await escrow.connect(maker).registerWallet();
    await escrow.connect(taker).registerWallet();
    await escrow.connect(attacker).registerWallet();
    await time.increase(SEVEN_DAYS + 1);

    // Fund taker and attacker with native ETH (dust limit anti-sybil check)
    await owner.sendTransaction({ to: taker.address,    value: ethers.parseEther("0.1") });
    await owner.sendTransaction({ to: attacker.address, value: ethers.parseEther("0.1") });

    // ── Boost loop: complete 200 Tier 0 trades → reach Tier 4
    // Tier 0 limit = 150 USDT → using 1 USDT per trade
    // Tier 0/1 cooldown = 4h → wait FOUR_HOURS + 1s between trades
    const dummyAmount = ethers.parseUnits("1", USDT_DECIMALS);

    for (let i = 0; i < Number(BASELINE_SUCCESS); i++) {
      const tx = await escrow.connect(maker).createEscrow(tokenAddr, dummyAmount, 0);
      const receipt = await tx.wait();
      const log = receipt.logs.find(l => {
        try { return escrow.interface.parseLog(l).name === "EscrowCreated"; }
        catch { return false; }
      });
      const tradeId = escrow.interface.parseLog(log).args.tradeId;

      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "setup");
      await escrow.connect(maker).releaseFunds(tradeId);

      await time.increase(FOUR_HOURS + 1);  // Tier 0 cooldown = 4h
    }

    return { escrow, mockUSDT, owner, treasury, maker, taker, attacker, stranger };
  }

  beforeEach(async () => {
    const f = await loadFixture(deployAndSetupFixture);
    escrow = f.escrow; mockUSDT = f.mockUSDT; owner = f.owner;
    treasury = f.treasury; maker = f.maker; taker = f.taker;
    attacker = f.attacker; stranger = f.stranger;
  });

  // ── Helpers ─────────────────────────────────────────────────────────────────

  /**
   * Creates an escrow for the given tier.
   * Uses TIER0_AMOUNT for Tier 0 (contract limit 150 USDT),
   * TRADE_AMOUNT for Tier 1+.
   */
  async function setupTrade(tierLevel = 2, amount = null) {
    const tradeAmount = amount ?? (tierLevel === 0 ? TIER0_AMOUNT : TRADE_AMOUNT);
    const tx = await escrow.connect(maker).createEscrow(
      await mockUSDT.getAddress(), tradeAmount, tierLevel
    );
    const receipt = await tx.wait();
    const log = receipt.logs.find(l => {
      try { return escrow.interface.parseLog(l).name === "EscrowCreated"; }
      catch { return false; }
    });
    return escrow.interface.parseLog(log).args.tradeId;
  }

  async function eip712CancelSig(signer, tradeId, nonce, deadline) {
    const domain = {
      name:              "ArafEscrow",
      version:           "1",
      chainId:           (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await escrow.getAddress(),
    };
    const types = {
      CancelProposal: [
        { name: "tradeId",  type: "uint256" },
        { name: "proposer", type: "address" },
        { name: "nonce",    type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    };
    return signer.signTypedData(domain, types, { tradeId, proposer: signer.address, nonce, deadline });
  }

  function calcFees(cryptoAmount, makerBond) {
    const takerFee       = (cryptoAmount * TAKER_FEE_BPS) / BPS_DENOM;
    const takerReceives  = cryptoAmount - takerFee;
    const makerFee       = (cryptoAmount * MAKER_FEE_BPS) / BPS_DENOM;
    const makerBondBack  = makerBond > makerFee ? makerBond - makerFee : 0n;
    const actualMakerFee = makerBond > makerFee ? makerFee : makerBond;
    return { takerFee, takerReceives, makerFee: actualMakerFee, makerBondBack,
             totalTreasury: takerFee + actualMakerFee };
  }

  /**
   * Causes 2 autoRelease failures for maker → triggers 1st ban (consecutiveBans=1).
   * Uses Tier 0 (TIER0_AMOUNT ≤ 150 USDT limit) with correct 48h+24h timing.
   */
  async function giveBanToMaker() {
    for (let i = 0; i < 2; i++) {
      const tradeId = await setupTrade(0);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, `QmBan${i}`);
      await time.increase(FORTY_EIGHT_H + 1);   // GRACE_PERIOD → pingMaker eligible
      await escrow.connect(taker).pingMaker(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);   // 24h response window → autoRelease eligible
      await escrow.connect(taker).autoRelease(tradeId);
      // 48h+24h = 72h elapsed >> 4h Tier0 cooldown → taker can lock again ✓
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. HAPPY PATH
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Happy Path", () => {

    it("full trade lifecycle: OPEN → LOCKED → PAID → RESOLVED", async () => {
      const tradeId = await setupTrade(2);

      await escrow.connect(taker).lockEscrow(tradeId);
      expect((await escrow.getTrade(tradeId)).state).to.equal(1);  // LOCKED

      await escrow.connect(taker).reportPayment(tradeId, "QmTestHashABC123");
      expect((await escrow.getTrade(tradeId)).state).to.equal(2);  // PAID

      const takerBefore = await mockUSDT.balanceOf(taker.address);
      const makerBefore = await mockUSDT.balanceOf(maker.address);
      await escrow.connect(maker).releaseFunds(tradeId);

      const { takerReceives, makerBondBack } = calcFees(TRADE_AMOUNT, MAKER_BOND_T2);
      expect(await mockUSDT.balanceOf(taker.address) - takerBefore)
        .to.equal(takerReceives + TAKER_BOND_T2);
      expect(await mockUSDT.balanceOf(maker.address) - makerBefore)
        .to.equal(makerBondBack);
      expect((await escrow.getTrade(tradeId)).state).to.equal(4);  // RESOLVED
    });

    it("taker can auto-release after GRACE_PERIOD (48h) ping + 24h wait", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmAutoRelease");

      // BUG FIX: pingMaker requires GRACE_PERIOD (48h) after paidAt — not 24h
      await time.increase(FORTY_EIGHT_H + 1);
      await escrow.connect(taker).pingMaker(tradeId);
      expect((await escrow.getTrade(tradeId)).pingedByTaker).to.be.true;

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(taker).autoRelease(tradeId);

      expect((await escrow.getTrade(tradeId)).state).to.equal(4);  // RESOLVED
      const [, makerFailed,,,] = await escrow.getReputation(maker.address);
      expect(makerFailed).to.equal(1n);
    });

    it("successful trade increments both parties' reputation", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");
      await escrow.connect(maker).releaseFunds(tradeId);

      const [makerSucc,,,] = await escrow.getReputation(maker.address);
      const [takerSucc,,,] = await escrow.getReputation(taker.address);
      expect(makerSucc).to.equal(BASELINE_SUCCESS + 1n);
      expect(takerSucc).to.equal(BASELINE_SUCCESS + 1n);
    });

    it("S1: autoRelease → maker +1 Failed, taker +1 Successful", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(FORTY_EIGHT_H + 1);
      await escrow.connect(taker).pingMaker(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(taker).autoRelease(tradeId);

      const [makerSucc, makerFail,,,] = await escrow.getReputation(maker.address);
      const [takerSucc, takerFail,,,] = await escrow.getReputation(taker.address);
      expect(makerSucc).to.equal(BASELINE_SUCCESS);
      expect(makerFail).to.equal(1n);
      expect(takerSucc).to.equal(BASELINE_SUCCESS + 1n);
      expect(takerFail).to.equal(0n);
    });

    it("S2: releaseFunds from CHALLENGED → maker +1 Failed (unjust challenge)", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).challengeTrade(tradeId);

      await escrow.connect(maker).releaseFunds(tradeId);

      const [, makerFail,,,] = await escrow.getReputation(maker.address);
      const [takerSucc, takerFail,,,] = await escrow.getReputation(taker.address);
      expect(makerFail).to.equal(1n);
      expect(takerSucc).to.equal(BASELINE_SUCCESS + 1n);
      expect(takerFail).to.equal(0n);
    });

    it("S3: collaborative cancel from CHALLENGED → no reputation penalty for either party", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).challengeTrade(tradeId);

      const deadline = (await time.latest()) + 3600;
      const makerSig = await eip712CancelSig(maker, tradeId, await escrow.sigNonces(maker.address), deadline);
      await escrow.connect(maker).proposeOrApproveCancel(tradeId, deadline, makerSig);
      const takerSig = await eip712CancelSig(taker, tradeId, await escrow.sigNonces(taker.address), deadline);
      await escrow.connect(taker).proposeOrApproveCancel(tradeId, deadline, takerSig);

      expect((await escrow.getTrade(tradeId)).state).to.equal(5);  // CANCELED
      const [, makerFail,,,] = await escrow.getReputation(maker.address);
      const [, takerFail,,,] = await escrow.getReputation(taker.address);
      expect(makerFail).to.equal(0n);
      expect(takerFail).to.equal(0n);
    });

    it("1st ban: 30 days, consecutiveBans=1, no tier restriction yet", async () => {
      await giveBanToMaker();

      const [, failed, bannedUntil, consecutive,] = await escrow.getReputation(maker.address);
      expect(failed).to.equal(2n);
      expect(bannedUntil).to.be.gt(0n);
      expect(consecutive).to.equal(1n);
      // hasTierPenalty is still false at 1st ban → effectiveTier returns 4 (unchanged)
      const [,,,,effectiveTier] = await escrow.getReputation(maker.address);
      expect(effectiveTier).to.equal(4);
      const now = BigInt(await time.latest());
      expect(bannedUntil).to.be.closeTo(now + BigInt(30 * 24 * 3600), 120n);
    });

    it("2nd consecutive ban: 60 days + maxAllowedTier drops to 3", async () => {
      for (let i = 0; i < 3; i++) {
        const tradeId = await setupTrade(0);
        await escrow.connect(taker).lockEscrow(tradeId);
        await escrow.connect(taker).reportPayment(tradeId, `QmHash${i}`);
        await time.increase(FORTY_EIGHT_H + 1);
        await escrow.connect(taker).pingMaker(tradeId);
        await time.increase(TWENTY_FOUR_H + 1);
        await escrow.connect(taker).autoRelease(tradeId);
        // Ban (bannedUntil) only prevents taker role — maker can still create escrows ✓
      }

      const [,, bannedUntil, consecutive, effectiveTier] = await escrow.getReputation(maker.address);
      expect(consecutive).to.equal(2n);
      expect(effectiveTier).to.equal(3);  // min(4, maxAllowedTier=3)
      const now = BigInt(await time.latest());
      expect(bannedUntil).to.be.closeTo(now + BigInt(60 * 24 * 3600), 120n);
    });

    it("tier-penalised maker cannot create listing above maxAllowedTier", async () => {
      for (let i = 0; i < 3; i++) {
        const tradeId = await setupTrade(0);
        await escrow.connect(taker).lockEscrow(tradeId);
        await escrow.connect(taker).reportPayment(tradeId, `QmHash${i}`);
        await time.increase(FORTY_EIGHT_H + 1);
        await escrow.connect(taker).pingMaker(tradeId);
        await time.increase(TWENTY_FOUR_H + 1);
        await escrow.connect(taker).autoRelease(tradeId);
      }

      // After 3 failures: consecutiveBans=2, maxAllowedTier=3
      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), TRADE_AMOUNT, 4)
      ).to.be.revertedWithCustomError(escrow, "TierNotAllowed");

      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), TRADE_AMOUNT, 3)
      ).to.not.be.reverted;
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. MAKER FLOW — Cancel OPEN Escrow
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Maker Flow — Cancel OPEN Escrow", () => {

    it("maker can cancel OPEN escrow and receive full refund", async () => {
      const tradeId    = await setupTrade(2);
      const makerBefore = await mockUSDT.balanceOf(maker.address);

      await escrow.connect(maker).cancelOpenEscrow(tradeId);

      expect(await mockUSDT.balanceOf(maker.address) - makerBefore)
        .to.equal(TOTAL_LOCK_T2);
      expect((await escrow.getTrade(tradeId)).state).to.equal(5);  // CANCELED
    });

    it("taker and stranger cannot cancel OPEN escrow", async () => {
      const tradeId = await setupTrade(2);
      await expect(escrow.connect(taker).cancelOpenEscrow(tradeId))
        .to.be.revertedWithCustomError(escrow, "OnlyMaker");
      await expect(escrow.connect(stranger).cancelOpenEscrow(tradeId))
        .to.be.revertedWithCustomError(escrow, "OnlyMaker");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. TIER 0 — Zero Bond, 4-Hour Cooldown
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Tier 0", () => {

    it("maker and taker bonds are zero", async () => {
      const tradeId = await setupTrade(0);
      const trade   = await escrow.getTrade(tradeId);
      expect(trade.makerBond).to.equal(0n);
      // takerBond set after lockEscrow — also 0 for Tier 0
    });

    it("taker does not send any bond on lockEscrow", async () => {
      const tradeId    = await setupTrade(0);
      const takerBefore = await mockUSDT.balanceOf(taker.address);
      await escrow.connect(taker).lockEscrow(tradeId);
      expect(await mockUSDT.balanceOf(taker.address)).to.equal(takerBefore);
    });

    it("happy path release — only protocol fee deducted, no bond", async () => {
      const tradeId = await setupTrade(0);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");
      const takerBefore = await mockUSDT.balanceOf(taker.address);
      await escrow.connect(maker).releaseFunds(tradeId);

      const takerFee = (TIER0_AMOUNT * TAKER_FEE_BPS) / BPS_DENOM;
      expect(await mockUSDT.balanceOf(taker.address) - takerBefore)
        .to.equal(TIER0_AMOUNT - takerFee);
    });

    it("dispute: only crypto decays (no bonds to bleed)", async () => {
      const tradeId = await setupTrade(0);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).challengeTrade(tradeId);

      // Past GRACE(48h) + USDT_DECAY_START(96h) = 144h → crypto decaying
      await time.increase(FORTY_EIGHT_H + 97 * ONE_HOUR);
      const [currCrypto, currMB, currTB,] = await escrow.getCurrentAmounts(tradeId);
      expect(currMB).to.equal(0n);
      expect(currTB).to.equal(0n);
      expect(currCrypto).to.be.lt(TIER0_AMOUNT);
    });

    it("4-hour cooldown enforced between Tier 0 trades", async () => {
      const tradeId  = await setupTrade(0);
      await escrow.connect(taker).lockEscrow(tradeId);
      const tradeId2 = await setupTrade(0);

      // Immediately → TierCooldownActive
      await expect(escrow.connect(taker).lockEscrow(tradeId2))
        .to.be.revertedWithCustomError(escrow, "TierCooldownActive");
    });

    it("second Tier 0 trade succeeds after 4h cooldown passes", async () => {
      const tradeId  = await setupTrade(0);
      await escrow.connect(taker).lockEscrow(tradeId);
      const tradeId2 = await setupTrade(0);

      await time.increase(FOUR_HOURS + 1);
      await expect(escrow.connect(taker).lockEscrow(tradeId2)).to.not.be.reverted;
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. TIER AMOUNT LIMITS — K-05 (C-04 on-chain enforcement)
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Tier Amount Limits (C-04)", () => {

    it("Tier 0: rejects amount > 150 USDT", async () => {
      const overLimit = ethers.parseUnits("151", USDT_DECIMALS);
      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), overLimit, 0)
      ).to.be.revertedWithCustomError(escrow, "AmountExceedsTierLimit");
    });

    it("Tier 0: accepts exact limit of 150 USDT", async () => {
      const atLimit = ethers.parseUnits("150", USDT_DECIMALS);
      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), atLimit, 0)
      ).to.not.be.reverted;
    });

    it("Tier 1: rejects amount > 1500 USDT", async () => {
      const overLimit = ethers.parseUnits("1501", USDT_DECIMALS);
      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), overLimit, 1)
      ).to.be.revertedWithCustomError(escrow, "AmountExceedsTierLimit");
    });

    it("Tier 1: accepts exact limit of 1500 USDT", async () => {
      const atLimit = ethers.parseUnits("1500", USDT_DECIMALS);
      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), atLimit, 1)
      ).to.not.be.reverted;
    });

    it("Tier 2: rejects amount > 7500 USDT", async () => {
      const overLimit = ethers.parseUnits("7501", USDT_DECIMALS);
      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), overLimit, 2)
      ).to.be.revertedWithCustomError(escrow, "AmountExceedsTierLimit");
    });

    it("Tier 2: accepts amount within limit", async () => {
      const withinLimit = ethers.parseUnits("7500", USDT_DECIMALS);
      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), withinLimit, 2)
      ).to.not.be.reverted;
    });

    it("Tier 3: rejects amount > 30000 USDT", async () => {
      const overLimit = ethers.parseUnits("30001", USDT_DECIMALS);
      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), overLimit, 3)
      ).to.be.revertedWithCustomError(escrow, "AmountExceedsTierLimit");
    });

    it("Tier 4: no upper limit (unlimited)", async () => {
      // Use 31000 USDT — above Tier 3 limit but within maker's balance
      const largeAmount = ethers.parseUnits("31000", USDT_DECIMALS);
      await expect(
        escrow.connect(maker).createEscrow(await mockUSDT.getAddress(), largeAmount, 4)
      ).to.not.be.reverted;
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. ANTI-SYBIL SHIELD
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Anti-Sybil Shield", () => {

    it("blocks self-trade", async () => {
      const tradeId = await setupTrade(1);
      await expect(escrow.connect(maker).lockEscrow(tradeId))
        .to.be.revertedWithCustomError(escrow, "SelfTradeForbidden");
    });

    it("blocks unregistered wallet", async () => {
      const tradeId = await setupTrade(1);
      await expect(escrow.connect(stranger).lockEscrow(tradeId))
        .to.be.revertedWithCustomError(escrow, "WalletTooYoung");
    });

    it("blocks freshly registered wallet (registered < 7 days ago)", async () => {
      const tradeId = await setupTrade(1);
      await escrow.connect(stranger).registerWallet();
      await time.increase(3 * 24 * 3600);  // Only 3 days, not 7

      await owner.sendTransaction({ to: stranger.address, value: ethers.parseEther("0.01") });
      await mockUSDT.mint(stranger.address, INITIAL_BAL);
      await mockUSDT.connect(stranger).approve(await escrow.getAddress(), ethers.MaxUint256);

      await expect(escrow.connect(stranger).lockEscrow(tradeId))
        .to.be.revertedWithCustomError(escrow, "WalletTooYoung");
    });

    it("blocks Tier 1 taker on 4-hour cooldown", async () => {
      const tradeId1 = await setupTrade(1);
      await escrow.connect(taker).lockEscrow(tradeId1);
      await escrow.connect(taker).reportPayment(tradeId1, "QmHash1");
      await escrow.connect(maker).releaseFunds(tradeId1);

      const tradeId2 = await setupTrade(1);
      await expect(escrow.connect(taker).lockEscrow(tradeId2))
        .to.be.revertedWithCustomError(escrow, "TierCooldownActive");

      // 4h cooldown (not 24h)
      await time.increase(FOUR_HOURS + 1);
      await expect(escrow.connect(taker).lockEscrow(tradeId2)).to.not.be.reverted;
    });

    it("blocks banned takers (2 burnExpired failures → ban)", async () => {
      for (let i = 0; i < 2; i++) {
        const tradeId = await setupTrade(2);
        await escrow.connect(taker).lockEscrow(tradeId);
        await escrow.connect(taker).reportPayment(tradeId, `QmHash${i}`);
        await time.increase(TWENTY_FOUR_H + 1);
        await escrow.connect(maker).pingTakerForChallenge(tradeId);
        await time.increase(TWENTY_FOUR_H + 1);
        await escrow.connect(maker).challengeTrade(tradeId);
        await time.increase(TEN_DAYS + 1);
        await escrow.burnExpired(tradeId);
      }

      const newTradeId = await setupTrade(2);
      await expect(escrow.connect(taker).lockEscrow(newTradeId))
        .to.be.revertedWithCustomError(escrow, "TakerBanActive");
    });

    it("ConflictingPingPath: taker cannot pingMaker after maker's pingTakerForChallenge", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);

      // Taker's autoRelease path is now blocked
      await time.increase(TWENTY_FOUR_H + 1);  // Past grace period
      await expect(escrow.connect(taker).pingMaker(tradeId))
        .to.be.revertedWithCustomError(escrow, "ConflictingPingPath");
    });

    it("ConflictingPingPath: maker cannot pingTakerForChallenge after taker's pingMaker", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(FORTY_EIGHT_H + 1);  // GRACE_PERIOD for pingMaker
      await escrow.connect(taker).pingMaker(tradeId);

      // Maker's challenge path is now blocked
      await expect(escrow.connect(maker).pingTakerForChallenge(tradeId))
        .to.be.revertedWithCustomError(escrow, "ConflictingPingPath");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. DISPUTE — BLEEDING ESCROW
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Bleeding Escrow", () => {

    it("challengeTrade reverts without prior pingTakerForChallenge (MustPingFirst)", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await expect(escrow.connect(maker).challengeTrade(tradeId))
        .to.be.revertedWithCustomError(escrow, "MustPingFirst");
    });

    it("challengeTrade reverts if 24h response window is still active", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);

      // Ping was just sent — 24h window not yet elapsed
      await expect(escrow.connect(maker).challengeTrade(tradeId))
        .to.be.revertedWithCustomError(escrow, "ResponseWindowActive");
    });

    it("maker can challenge after full ping-wait cycle (24h + 24h)", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).challengeTrade(tradeId);

      expect((await escrow.getTrade(tradeId)).state).to.equal(3);  // CHALLENGED
    });

    it("maker can release funds during the bleeding phase", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).challengeTrade(tradeId);
      await time.increase(FORTY_EIGHT_H + 2 * 24 * 3600);  // Deep into bleeding

      const takerBefore = await mockUSDT.balanceOf(taker.address);
      await escrow.connect(maker).releaseFunds(tradeId);
      expect(await mockUSDT.balanceOf(taker.address)).to.be.gt(takerBefore);
      expect((await escrow.getTrade(tradeId)).state).to.equal(4);  // RESOLVED
    });

    it("collateral decays per-second after grace period (no step-function)", async () => {
      const tradeId = await setupTrade(1);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).challengeTrade(tradeId);

      // During grace period (48h) — zero decay
      const [, mb0,, d0] = await escrow.getCurrentAmounts(tradeId);
      expect(d0).to.equal(0n);

      await time.increase(FORTY_EIGHT_H);
      const [,,, dGrace] = await escrow.getCurrentAmounts(tradeId);
      expect(dGrace).to.equal(0n);

      // 1h into bleeding — decay begins
      await time.increase(ONE_HOUR);
      const [, mb1h,, d1h] = await escrow.getCurrentAmounts(tradeId);
      expect(d1h).to.be.gt(0n);
      expect(mb1h).to.be.lt(mb0);

      // 24h into bleeding — more decay
      await time.increase(23 * ONE_HOUR);
      const [, mb24h,, d24h] = await escrow.getCurrentAmounts(tradeId);
      expect(d24h).to.be.gt(d1h);
      expect(mb24h).to.be.lt(mb1h);
    });

    it("crypto decay starts only after Grace(48h) + USDT_DECAY_START(96h) = 144h", async () => {
      const tradeId = await setupTrade(1);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).challengeTrade(tradeId);

      // At 143h from challengedAt — no crypto decay yet
      await time.increase(FORTY_EIGHT_H + 95 * ONE_HOUR);
      const [crypto143,,,] = await escrow.getCurrentAmounts(tradeId);
      expect(crypto143).to.equal(TRADE_AMOUNT);

      // At 145h — crypto decay active
      await time.increase(2 * ONE_HOUR);
      const [crypto145,,,] = await escrow.getCurrentAmounts(tradeId);
      expect(crypto145).to.be.lt(TRADE_AMOUNT);
    });

    it("burnExpired transfers all remaining funds to treasury after 10 days", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).challengeTrade(tradeId);
      await time.increase(TEN_DAYS + 1);

      const treasuryBefore = await mockUSDT.balanceOf(treasury.address);
      await escrow.burnExpired(tradeId);

      expect(await mockUSDT.balanceOf(treasury.address)).to.be.gt(treasuryBefore);
      expect((await escrow.getTrade(tradeId)).state).to.equal(6);  // BURNED
    });

    it("both parties receive +1 Failed after burn", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).pingTakerForChallenge(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);
      await escrow.connect(maker).challengeTrade(tradeId);
      await time.increase(TEN_DAYS + 1);
      await escrow.burnExpired(tradeId);

      const [, makerFail,,,] = await escrow.getReputation(maker.address);
      const [, takerFail,,,] = await escrow.getReputation(taker.address);
      expect(makerFail).to.equal(1n);
      expect(takerFail).to.equal(1n);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. COLLABORATIVE CANCEL — EIP-712
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Collaborative Cancel (EIP-712)", () => {

    it("requires both parties' signatures before cancellation executes", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);

      const deadline = (await time.latest()) + 3600;
      const makerSig = await eip712CancelSig(maker, tradeId, await escrow.sigNonces(maker.address), deadline);
      await escrow.connect(maker).proposeOrApproveCancel(tradeId, deadline, makerSig);

      expect((await escrow.getTrade(tradeId)).state).to.equal(1);  // Still LOCKED

      const takerSig = await eip712CancelSig(taker, tradeId, await escrow.sigNonces(taker.address), deadline);
      await escrow.connect(taker).proposeOrApproveCancel(tradeId, deadline, takerSig);

      expect((await escrow.getTrade(tradeId)).state).to.equal(5);  // CANCELED
    });

    it("cancel in LOCKED state: zero protocol fee, full refund to both parties", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);

      const makerBefore    = await mockUSDT.balanceOf(maker.address);
      const takerBefore    = await mockUSDT.balanceOf(taker.address);
      const treasuryBefore = await mockUSDT.balanceOf(treasury.address);

      const deadline = (await time.latest()) + 3600;
      const makerSig = await eip712CancelSig(maker, tradeId, await escrow.sigNonces(maker.address), deadline);
      await escrow.connect(maker).proposeOrApproveCancel(tradeId, deadline, makerSig);
      const takerSig = await eip712CancelSig(taker, tradeId, await escrow.sigNonces(taker.address), deadline);
      await escrow.connect(taker).proposeOrApproveCancel(tradeId, deadline, takerSig);

      expect(await mockUSDT.balanceOf(maker.address)    - makerBefore).to.equal(TOTAL_LOCK_T2);
      expect(await mockUSDT.balanceOf(taker.address)    - takerBefore).to.equal(TAKER_BOND_T2);
      expect(await mockUSDT.balanceOf(treasury.address) - treasuryBefore).to.equal(0n);
    });

    it("cancel in PAID state: standard 0.2% protocol fee deducted", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmTestHash");  // PAID

      const makerBefore    = await mockUSDT.balanceOf(maker.address);
      const takerBefore    = await mockUSDT.balanceOf(taker.address);
      const treasuryBefore = await mockUSDT.balanceOf(treasury.address);

      const deadline = (await time.latest()) + 3600;
      const makerSig = await eip712CancelSig(maker, tradeId, await escrow.sigNonces(maker.address), deadline);
      await escrow.connect(maker).proposeOrApproveCancel(tradeId, deadline, makerSig);
      const takerSig = await eip712CancelSig(taker, tradeId, await escrow.sigNonces(taker.address), deadline);
      await escrow.connect(taker).proposeOrApproveCancel(tradeId, deadline, takerSig);

      const takerFee = (TRADE_AMOUNT * TAKER_FEE_BPS) / BPS_DENOM;
      const makerFee = (TRADE_AMOUNT * MAKER_FEE_BPS) / BPS_DENOM;

      expect(await mockUSDT.balanceOf(maker.address)    - makerBefore)
        .to.equal(TRADE_AMOUNT + MAKER_BOND_T2 - makerFee);
      expect(await mockUSDT.balanceOf(taker.address)    - takerBefore)
        .to.equal(TAKER_BOND_T2 - takerFee);
      expect(await mockUSDT.balanceOf(treasury.address) - treasuryBefore)
        .to.equal(takerFee + makerFee);
    });

    it("rejects expired signatures (SignatureExpired)", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);

      const deadline = (await time.latest()) - 1;
      const sig = await eip712CancelSig(maker, tradeId, await escrow.sigNonces(maker.address), deadline);
      await expect(escrow.connect(maker).proposeOrApproveCancel(tradeId, deadline, sig))
        .to.be.revertedWithCustomError(escrow, "SignatureExpired");
    });

    it("rejects replayed signatures (InvalidSignature via nonce)", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);

      const deadline = (await time.latest()) + 3600;
      const nonce = await escrow.sigNonces(maker.address);
      const sig   = await eip712CancelSig(maker, tradeId, nonce, deadline);

      await escrow.connect(maker).proposeOrApproveCancel(tradeId, deadline, sig);
      // Nonce incremented — same sig is now invalid
      await expect(escrow.connect(maker).proposeOrApproveCancel(tradeId, deadline, sig))
        .to.be.revertedWithCustomError(escrow, "InvalidSignature");
    });

    it("rejects deadline exceeding MAX_CANCEL_DEADLINE (7 days)", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);

      const deadline = (await time.latest()) + 8 * 24 * 3600;  // 8 days — over limit
      const sig = await eip712CancelSig(maker, tradeId, await escrow.sigNonces(maker.address), deadline);
      await expect(escrow.connect(maker).proposeOrApproveCancel(tradeId, deadline, sig))
        .to.be.revertedWithCustomError(escrow, "DeadlineTooFar");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 8. REENTRANCY GUARD
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Reentrancy Guard", () => {

    it("releaseFunds cannot be called twice on same trade (CannotReleaseInState)", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");
      await escrow.connect(maker).releaseFunds(tradeId);

      await expect(escrow.connect(maker).releaseFunds(tradeId))
        .to.be.revertedWithCustomError(escrow, "CannotReleaseInState");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 9. BOND & FEE CALCULATIONS
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Bond & Fee Calculations", () => {

    it("treasury receives 0.2% total (0.1% from each party)", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      const treasuryBefore = await mockUSDT.balanceOf(treasury.address);
      await escrow.connect(maker).releaseFunds(tradeId);

      const { totalTreasury } = calcFees(TRADE_AMOUNT, MAKER_BOND_T2);
      expect(await mockUSDT.balanceOf(treasury.address) - treasuryBefore)
        .to.equal(totalTreasury);
    });

    it("taker receives crypto minus taker fee, plus own bond", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      const takerBefore = await mockUSDT.balanceOf(taker.address);
      await escrow.connect(maker).releaseFunds(tradeId);

      const { takerReceives } = calcFees(TRADE_AMOUNT, MAKER_BOND_T2);
      expect(await mockUSDT.balanceOf(taker.address) - takerBefore)
        .to.equal(takerReceives + TAKER_BOND_T2);
    });

    it("maker receives bond minus maker fee", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      const makerBefore = await mockUSDT.balanceOf(maker.address);
      await escrow.connect(maker).releaseFunds(tradeId);

      const { makerBondBack } = calcFees(TRADE_AMOUNT, MAKER_BOND_T2);
      expect(await mockUSDT.balanceOf(maker.address) - makerBefore)
        .to.equal(makerBondBack);
    });

    it("autoRelease applies 2% negligence penalty (AUTO_RELEASE_PENALTY_BPS=200), not standard fee", async () => {
      const tradeId = await setupTrade(2);
      await escrow.connect(taker).lockEscrow(tradeId);
      await escrow.connect(taker).reportPayment(tradeId, "QmHash");

      await time.increase(FORTY_EIGHT_H + 1);
      await escrow.connect(taker).pingMaker(tradeId);
      await time.increase(TWENTY_FOUR_H + 1);

      const takerBefore    = await mockUSDT.balanceOf(taker.address);
      const makerBefore    = await mockUSDT.balanceOf(maker.address);
      const treasuryBefore = await mockUSDT.balanceOf(treasury.address);

      await escrow.connect(taker).autoRelease(tradeId);

      const makerPenalty = (MAKER_BOND_T2 * 200n) / BPS_DENOM;
      const takerPenalty = (TAKER_BOND_T2 * 200n) / BPS_DENOM;

      expect(await mockUSDT.balanceOf(taker.address)    - takerBefore)
        .to.equal(TRADE_AMOUNT + (TAKER_BOND_T2 - takerPenalty));
      expect(await mockUSDT.balanceOf(maker.address)    - makerBefore)
        .to.equal(MAKER_BOND_T2 - makerPenalty);
      expect(await mockUSDT.balanceOf(treasury.address) - treasuryBefore)
        .to.equal(makerPenalty + takerPenalty);
    });

    it("Tier 0 taker pays zero bond on lock", async () => {
      const tradeId    = await setupTrade(0);
      const takerBefore = await mockUSDT.balanceOf(taker.address);
      await escrow.connect(taker).lockEscrow(tradeId);
      expect(await mockUSDT.balanceOf(taker.address)).to.equal(takerBefore);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 10. REPUTATION DECAY — Clean Slate Rule
  // ═══════════════════════════════════════════════════════════════════════════
  describe("Reputation Decay (Clean Slate)", () => {

    it("resets consecutiveBans after 180 clean days post-ban", async () => {
      await giveBanToMaker();

      const [,, bannedUntil, consecutiveBefore,] = await escrow.getReputation(maker.address);
      expect(consecutiveBefore).to.equal(1n);

      const cleanSlatePeriod = 180 * 24 * 3600;
      await time.increase(
        (bannedUntil - BigInt(await time.latest())) + BigInt(cleanSlatePeriod) + 3601n
      );

      await expect(escrow.decayReputation(maker.address))
        .to.emit(escrow, "ReputationUpdated");

      const [,,, consecutiveAfter,] = await escrow.getReputation(maker.address);
      expect(consecutiveAfter).to.equal(0n);
    });

    it("reverts for wallet with no prior ban history (NoPriorBanHistory)", async () => {
      await expect(escrow.decayReputation(stranger.address))
        .to.be.revertedWithCustomError(escrow, "NoPriorBanHistory");
    });

    it("reverts if 180-day clean period has not elapsed (CleanPeriodNotElapsed)", async () => {
      await giveBanToMaker();
      const [,, bannedUntil,,] = await escrow.getReputation(maker.address);

      await time.increase(
        (bannedUntil - BigInt(await time.latest())) + BigInt(170 * 24 * 3600)
      );

      await expect(escrow.decayReputation(maker.address))
        .to.be.revertedWithCustomError(escrow, "CleanPeriodNotElapsed");
    });

    it("reverts if consecutiveBans already zero (NoBansToReset)", async () => {
      await giveBanToMaker();
      const [,, bannedUntil,,] = await escrow.getReputation(maker.address);
      await time.increase(
        (bannedUntil - BigInt(await time.latest())) + BigInt(180 * 24 * 3600) + 3601n
      );

      await escrow.decayReputation(maker.address);  // First reset

      await expect(escrow.decayReputation(maker.address))
        .to.be.revertedWithCustomError(escrow, "NoBansToReset");
    });
  });
});
