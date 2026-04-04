// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockERC20 — Araf Testnet Faucet + Test Fixture Token
 *
 * BACK-08 Fix: Admin mint() fonksiyonuna onlyOwner eklendi.
 *   ÖNCEKİ: mint(address to, uint256 amount) herhangi bir erişim kısıtlaması içermiyordu.
 *   Kontrat yanlışlıkla testnet veya mainnet ortamına bu haliyle deploy edilirse,
 *   herhangi bir kullanıcı sınırsız miktarda token basarak protokolün tüm ekonomik
 *   dengesini saniyeler içinde yok edebilirdi.
 *   ŞİMDİ: onlyOwner modifier eklendi.
 *   UYARI: Bu kontrat yalnızca geliştirme/testnet içindir. Mainnet'e ASLA deploy etmeyin.
 *
 * İki mint yolu:
 *   1. mint()                — Kullanıcı faucet'i. Saatte 1000 token, rate-limited.
 *   2. mint(address, uint256) — Test fixture kurulumu için. Sadece owner çağırabilir.
 */
contract MockERC20 is ERC20, Ownable {
    uint8 private _dec;

    // [TR] Anti-spam: Her cüzdan için son mint zamanı
    mapping(address => uint256) public lastMintTime;

    constructor(string memory name, string memory symbol, uint8 decimals_)
        ERC20(name, symbol)
        Ownable(msg.sender)
    {
        _dec = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _dec;
    }

    /**
     * @notice Testnet faucet — Saatte 1000 token (rate-limited).
     * @dev Herhangi bir kullanıcı çağırabilir.
     */
    function mint() external {
        require(
            block.timestamp >= lastMintTime[msg.sender] + 1 hours,
            "MockERC20: Saatte sadece 1000 token basabilirsiniz."
        );
        lastMintTime[msg.sender] = block.timestamp;
        _mint(msg.sender, 1000 * 10 ** decimals());
    }

    /**
     * @notice Hardhat test fixture kurulumu için kısıtlı admin mint.
     * @dev BACK-08 Fix: Sadece owner çağırabilir (onlyOwner eklendi).
     *      Bu fonksiyon YALNIZCA test ortamında kullanılmalıdır.
     *      Production token kontratlarında bu fonksiyon BULUNMAMALIDIR.
     * @param to     Alıcı adres
     * @param amount Basılacak miktar (token decimals cinsinden)
     */
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
