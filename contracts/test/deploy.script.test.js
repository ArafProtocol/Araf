const { expect } = require("chai");
const { resolveProductionTokenConfig } = require("../scripts/deploy");

describe("deploy script config guards", function () {
  const OLD_NODE_ENV = process.env.NODE_ENV;
  const OLD_USDT = process.env.MAINNET_USDT_ADDRESS;
  const OLD_USDC = process.env.MAINNET_USDC_ADDRESS;

  after(function () {
    process.env.NODE_ENV = OLD_NODE_ENV;
    process.env.MAINNET_USDT_ADDRESS = OLD_USDT;
    process.env.MAINNET_USDC_ADDRESS = OLD_USDC;
  });

  beforeEach(function () {
    delete process.env.MAINNET_USDT_ADDRESS;
    delete process.env.MAINNET_USDC_ADDRESS;
    process.env.NODE_ENV = "production";
  });

  it("fails fast when production token env vars are missing", function () {
    expect(() => resolveProductionTokenConfig()).to.throw(/MAINNET_USDT_ADDRESS/);
  });

  it("accepts valid production token env vars", function () {
    process.env.MAINNET_USDT_ADDRESS = "0x1111111111111111111111111111111111111111";
    process.env.MAINNET_USDC_ADDRESS = "0x2222222222222222222222222222222222222222";

    const cfg = resolveProductionTokenConfig();
    expect(cfg.isProduction).to.equal(true);
    expect(cfg.usdtAddress).to.equal("0x1111111111111111111111111111111111111111");
    expect(cfg.usdcAddress).to.equal("0x2222222222222222222222222222222222222222");
  });

  it("fails fast when production token env vars are zero addresses", function () {
    process.env.MAINNET_USDT_ADDRESS = "0x0000000000000000000000000000000000000000";
    process.env.MAINNET_USDC_ADDRESS = "0x2222222222222222222222222222222222222222";

    expect(() => resolveProductionTokenConfig()).to.throw(/MAINNET_USDT_ADDRESS/);
  });

  it("fails fast when production token env vars are invalid addresses", function () {
    process.env.MAINNET_USDT_ADDRESS = "not-an-address";
    process.env.MAINNET_USDC_ADDRESS = "0x2222222222222222222222222222222222222222";

    expect(() => resolveProductionTokenConfig()).to.throw();
  });

  it("is mock-friendly in non-production mode", function () {
    process.env.NODE_ENV = "test";

    const cfg = resolveProductionTokenConfig();
    expect(cfg.isProduction).to.equal(false);
    expect(cfg.usdtAddress).to.equal(null);
    expect(cfg.usdcAddress).to.equal(null);
  });
});
