"""Generator script to produce a balanced, realistic, annotated 120-contract feature dataset."""

import csv
import random
from pathlib import Path

random.seed(42)

BENIGN_PROFILES = [
    # (name, origin, loc, n_fn, n_mod, has_transfer, has_owner, num_pos, oz, renounce)
    ("DAI_Stablecoin", "MakerDAO Core Contracts", 320, 24, 3, 1, 1, 4, 1, 1),
    ("USDC_Token", "Centre Consortium Etherscan Verified", 450, 32, 4, 1, 1, 4, 1, 0),
    ("USDT_Token", "Tether Etherscan Verified", 380, 28, 3, 1, 1, 2, 0, 0),
    ("Uniswap_UNI", "Uniswap Governance Token", 210, 16, 2, 1, 1, 4, 1, 1),
    ("Chainlink_LINK", "Chainlink Token Contract", 280, 22, 3, 1, 1, 3, 1, 1),
    ("Aave_AAVE", "Aave Token v2", 340, 26, 3, 1, 1, 4, 1, 1),
    ("Wrapped_BTC", "BitGo WBTC Contract", 260, 20, 2, 1, 1, 3, 1, 0),
    ("Compound_COMP", "Compound Governance", 230, 18, 2, 1, 1, 4, 1, 1),
    ("Curve_CRV", "Curve Finance DAO", 310, 25, 3, 1, 1, 3, 1, 1),
    ("Maker_MKR", "Maker Protocol Governance", 290, 22, 2, 1, 1, 4, 1, 1),
    ("Synthetix_SNX", "Synthetix Network Token", 410, 35, 4, 1, 1, 3, 1, 0),
    ("SushiSwap_SUSHI", "SushiSwap Core Token", 190, 15, 2, 1, 1, 4, 1, 1),
    ("Balancer_BAL", "Balancer Governance Token", 220, 17, 2, 1, 1, 4, 1, 1),
    ("1inch_1INCH", "1inch Network Token", 270, 21, 2, 1, 1, 4, 1, 1),
    ("Yearn_YFI", "Yearn Finance Token", 180, 14, 1, 1, 1, 4, 1, 1),
    ("Lido_LDO", "Lido DAO Token", 250, 19, 2, 1, 1, 4, 1, 1),
    ("RocketPool_RPL", "Rocket Pool Protocol", 360, 28, 3, 1, 1, 3, 1, 1),
    ("EthereumNameService_ENS", "ENS Governance Token", 240, 18, 2, 1, 1, 4, 1, 1),
    ("Frax_FRAX", "Frax Protocol Stablecoin", 390, 30, 4, 1, 1, 3, 1, 0),
    ("FraxShare_FXS", "Frax Share Token", 350, 27, 3, 1, 1, 3, 1, 0),
    ("TheGraph_GRT", "The Graph Protocol", 300, 23, 2, 1, 1, 4, 1, 1),
    ("BasicAttention_BAT", "Brave BAT Token", 210, 16, 2, 1, 1, 3, 0, 1),
    ("Enjin_ENJ", "Enjin Coin Contract", 260, 20, 2, 1, 1, 3, 1, 0),
    ("Decentraland_MANA", "Decentraland Token", 240, 18, 2, 1, 1, 3, 1, 0),
    ("Sandbox_SAND", "The Sandbox Token", 320, 24, 3, 1, 1, 4, 1, 1),
    ("Pepe_PEPE", "Pepe Standard Meme ERC20", 175, 12, 1, 1, 0, 3, 1, 1),
    ("ShibaInu_SHIB", "Shiba Inu Token Contract", 195, 14, 1, 1, 0, 3, 0, 1),
    ("Arbitrum_ARB", "Arbitrum Token Contract", 280, 22, 2, 1, 1, 4, 1, 1),
    ("Optimism_OP", "Optimism Token Contract", 260, 20, 2, 1, 1, 4, 1, 1),
    ("Polygon_POL", "Polygon Ecosystem Token", 330, 25, 3, 1, 1, 4, 1, 1),
    # OpenZeppelin Presets & Standards
    ("OZ_ERC20PresetFixed", "OpenZeppelin v4.9 Preset", 120, 8, 1, 1, 0, 4, 1, 1),
    ("OZ_ERC20Permit", "OpenZeppelin v4.9 Permit", 160, 11, 1, 1, 0, 4, 1, 1),
    ("OZ_ERC20Votes", "OpenZeppelin v4.9 Governance", 210, 15, 2, 1, 0, 4, 1, 1),
    ("OZ_ERC20Wrapper", "OpenZeppelin v4.9 Wrapper", 140, 10, 1, 1, 0, 4, 1, 1),
    ("OZ_ERC20Burnable", "OpenZeppelin v4.9 Burnable", 130, 9, 1, 1, 0, 4, 1, 1),
    ("OZ_ERC20Capped", "OpenZeppelin v4.9 Capped", 135, 9, 1, 1, 1, 4, 1, 1),
    ("OZ_ERC20FlashMint", "OpenZeppelin v4.9 FlashMint", 170, 12, 2, 1, 0, 4, 1, 1),
    ("OZ_ERC20Pausable_Safe", "OpenZeppelin v4.9 Pausable Capped", 185, 13, 2, 1, 1, 4, 1, 1),
    ("OZ_ERC20Snapshot", "OpenZeppelin v4.9 Snapshot", 190, 14, 2, 1, 1, 4, 1, 1),
    ("OZ_ERC20Upgradeable", "OpenZeppelin Upgradeable v4", 230, 18, 3, 1, 1, 4, 1, 1),
    # DeFi Liquidity & Vaults
    ("UniswapV2_Pair_ETH_USDT", "Uniswap v2 Core Pair", 280, 21, 2, 1, 0, 3, 0, 1),
    ("UniswapV2_Pair_ETH_DAI", "Uniswap v2 Core Pair", 280, 21, 2, 1, 0, 3, 0, 1),
    ("Sushiswap_Pair_WBTC_ETH", "SushiSwap Core Pair", 285, 21, 2, 1, 0, 3, 0, 1),
    ("Curve_3Pool_LP", "Curve Stableswap LP Token", 310, 22, 2, 1, 0, 3, 0, 1),
    ("Yearn_Vault_yvUSDC", "Yearn v2 Vault Token", 420, 32, 4, 1, 1, 4, 1, 1),
    ("Compound_cDAI", "Compound Money Market cToken", 450, 36, 4, 1, 1, 3, 0, 0),
    ("Compound_cUSDC", "Compound Money Market cToken", 450, 36, 4, 1, 1, 3, 0, 0),
    ("Aave_aUSDT", "Aave v2 Interest Bearing Token", 380, 29, 3, 1, 1, 4, 1, 0),
    ("Aave_aWETH", "Aave v2 Interest Bearing Token", 380, 29, 3, 1, 1, 4, 1, 0),
    ("Stargate_LP_USDC", "Stargate Omnichain LP", 340, 25, 3, 1, 1, 4, 1, 1),
    # Reflection & Fee tokens with safe capped fees (< 5%)
    ("SafeTax_Reflect_1", "Audited Capped Tax Token (2%)", 310, 24, 3, 1, 1, 3, 1, 1),
    ("SafeTax_Community_2", "Audited Liquidity Fee Token (3%)", 295, 22, 2, 1, 1, 3, 1, 1),
    ("SafeTax_Charity_3", "Audited Staking Charity Token (1%)", 275, 20, 2, 1, 1, 3, 1, 1),
    ("SafeEcosystem_Token", "Community Governed DAO Token", 225, 17, 2, 1, 1, 4, 1, 1),
    ("GreenEnergy_DAO", "Environmental Carbon Credit Token", 310, 23, 2, 1, 1, 3, 1, 1),
    ("LiquidStaked_ETH", "Decentralized LST Protocol", 390, 30, 4, 1, 1, 4, 1, 1),
    ("MetaverseLand_Token", "Gaming Protocol In-Game Token", 260, 20, 2, 1, 1, 3, 1, 1),
    ("DecentralizedIdentity_ID", "Web3 Identity Attestation Token", 240, 18, 2, 1, 1, 4, 1, 1),
    ("CrossChain_Bridge_Token", "Multi-Sig Capped Bridge Token", 330, 26, 3, 1, 1, 4, 1, 1),
    ("BenignToken_Sample", "Local Benchmark Benign Token", 185, 14, 2, 1, 1, 4, 1, 1),
]

HONEYPOT_PROFILES = [
    # (name, origin, loc, n_fn, n_mod, has_transfer, has_owner, blk, sell_rst, exc_tax, unb_tax, cool, pause, max_lim, mint, asm, ext, num_pos, oz, ren)
    # 1. Blacklist Traps (8)
    ("SquidGame_ScamToken", "Squid Game Blacklist Scam 2021", 240, 16, 3, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("BabyFloki_Blacklist", "DEX Bot Bait Honeypot", 210, 14, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("SafeElon_BlacklistGate", "BSC Rugpull Blacklist Gate", 230, 15, 2, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
    ("Minereum_FakeAirdrop", "Dusting Airdrop Blacklist Trap", 180, 11, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("MetaSpace_Blocker", "Anti-Whale Blacklist Disguise", 260, 18, 3, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("ElonDoge_TrapGate", "Meme Blacklist Trap", 195, 13, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("ShibaShade_Blacklist", "Uniswap v2 Fake Shib Trap", 220, 15, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("DarkMatter_Blacklist", "Yield Farm Trap Blacklist", 280, 19, 3, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
    # 2. 99% Sell Tax Traps (8)
    ("GrimReaper_99Fee", "100% Tax Liquidity Burner", 190, 13, 2, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("ScamMoon_99Tax", "Uniswap Pair 99% Sell Fee Trap", 205, 14, 2, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("Titan_FeeManipulator", "90% Dynamic Sell Surcharge", 215, 15, 2, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("FakeUSDT_TaxDrainer", "Spoofed Stablecoin 95% Fee", 225, 15, 2, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("InfiniteBurn_DEXScam", "Pair Sell Deducts 99.9%", 185, 12, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("MegaPump_90Fee", "Marketing Fee 90% Drainer", 210, 14, 2, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("MoonShot_TaxTrap", "Uniswap Sell Tax 98%", 195, 13, 2, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("TurboRocket_99Tax", "DEX Sell Penalty 99%", 200, 14, 2, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    # 3. Asymmetric Sell Restrictions (6)
    ("OnlyBuy_Token", "Asymmetric Router Block", 175, 12, 2, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("AntiDump_PermanentTrap", "Sell Condition Always Reverts", 190, 13, 2, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("PancakeRouter_SellBlock", "PancakePair Destination Check", 230, 16, 2, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("LiquidityLocker_Scam", "Transfer To Pair Denied", 210, 14, 2, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("ZeroSell_PermitHoneypot", "Only Whitelisted Can Sell", 240, 16, 3, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("DEX_OneWayStreet", "Buy Allowed Sell Reverts", 185, 12, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    # 4. Unbounded Fee Setters (6)
    ("OwnerFee_PumpScam", "Admin SetFee(100) Unconstrained", 220, 15, 2, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("StealthFee_Trap", "Zero Initial Tax Then Set 99%", 205, 14, 2, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("DynamicTax_Rug", "SetSellFee Without Ceiling", 235, 16, 2, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("AdminFee_Drainer", "ModifyTransferFee Up To 100", 215, 14, 2, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("HiddenTax_Setter", "Owner-only Fee Alteration", 195, 13, 2, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ("ArbitraryFee_Token", "Unbounded Sell Tax Setter", 210, 14, 2, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    # 5. Cooldown / Anti-Bot Lockup (5)
    ("TimeLock_Drainer", "Transfer Cooldown 7 Days", 230, 15, 2, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
    ("BotKiller_Honeypot", "Block Number Transfer Trap", 215, 14, 2, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
    ("FreezeTransfer_Token", "AntiBot 24 Hour Transfer Freeze", 240, 16, 2, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
    ("IntervalLock_Scam", "Trading Delay 86400 Seconds", 225, 15, 2, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
    ("HoldersLock_Trap", "Wallet Holding Period Lockup", 205, 13, 2, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
    # 6. Pausable Transfer Traps (5)
    ("PerpetualPause_Scam", "Owner Pauses Transfers Forever", 195, 13, 2, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    ("TrapDoor_Pausable", "Owner Pauses Right After Listing", 210, 14, 2, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    ("FreezeTrading_Coin", "Emergency Pause Used As Honeypot", 220, 15, 2, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    ("SuspendedSell_Coin", "Sell Pausable Only By Creator", 200, 14, 2, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    ("OneClickPause_Token", "Owner Pause Without Unpause", 185, 12, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    # 7. Max Wallet / Micro Transaction Limits (5)
    ("MicroTx_ScamToken", "MaxTxAmount Set To 1 Wei", 215, 14, 2, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    ("OneWeiLimit_Trap", "Max Sell 1 Token Cent", 195, 13, 2, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    ("SlippageTrap_Coin", "Max Wallet Restricts Liquidation", 225, 15, 2, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    ("ZeroTransferLimit", "Max Transfer Set To Zero By Admin", 205, 14, 2, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    ("DustOnly_Token", "Max Sell Limit 0.0001% Supply", 210, 14, 2, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0),
    # 8. Hidden Mint Traps (5)
    ("SecretMint_Scam", "Public Mint Protected By Owner Only", 230, 15, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    ("InfinityPrinter_Token", "Owner Can Infinite Mint And Dump", 220, 14, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    ("BackdoorInflation_Scam", "Hidden Mint In Staking Function", 260, 18, 3, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    ("ShadowSupply_Coin", "Owner Mint Without Cap", 240, 16, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    ("AirdropMint_Drainer", "Batch Mint Exclusively For Owner", 215, 14, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    # 9. Inline Assembly & External Oracles (6)
    ("AssemblyBackdoor_Scam", "Inline Assembly Bypasses Transfer", 250, 16, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
    ("DelegateCall_Drainer", "DelegateCall In Transfer Hook", 280, 18, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
    ("RawStorageManipulator", "Assembly Writes Balance Directly", 260, 17, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
    ("ExternalOracle_Trap", "External Contract Gating Transfers", 270, 18, 2, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
    ("FakeRouterValidator", "External Sell Validation Hook", 290, 19, 3, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
    ("MaliciousHook_Token", "External Oracle Reverts DEX Sell", 275, 18, 2, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
    # 10. Multi-Vector Composite Honeypots (6)
    ("UltraRugPull_Combo", "Blacklist + 99% Sell Tax + Unbounded", 310, 20, 3, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0),
    ("FullSpectrum_Honeypot", "Multi-Vector Attack Suite", 350, 24, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0),
    ("ShadowAdmin_Scam", "Hidden Mint + Cooldown + Assembly", 285, 19, 3, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0),
    ("HoneypotToken_Sample", "Local Benchmark Honeypot Token", 340, 22, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0),
    ("DeFiVampire_Trap", "Blacklist + Sell Restriction + Pause", 295, 19, 3, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0),
    ("BlackHole_LiquidityTrap", "99% Fee + MicroTx Limit + Cooldown", 270, 17, 3, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0),
]


def generate_dataset_csv(output_path: Path):
    fieldnames = [
        "contract_id",
        "contract_name",
        "source_origin",
        "lines_of_code",
        "num_functions",
        "num_modifiers",
        "has_transfer_function",
        "has_owner_control",
        "has_blacklist_mapping",
        "has_sell_restriction_logic",
        "has_excessive_fee",
        "has_unbounded_fee_setter",
        "has_cooldown_delay",
        "has_pausable_transfers",
        "has_max_tx_wallet_limit",
        "has_hidden_mint",
        "has_inline_assembly",
        "has_external_transfer_call",
        "num_positive_indicators",
        "has_openzeppelin_imports",
        "has_renounce_ownership",
        "num_total_findings",
        "is_honeypot",
    ]

    rows = []

    # Process Benign profiles
    for i, p in enumerate(BENIGN_PROFILES, 1):
        name, origin, loc, n_fn, n_mod, has_transfer, has_owner, num_pos, oz, ren = p
        row = {
            "contract_id": f"BENIGN_{i:03d}",
            "contract_name": name,
            "source_origin": origin,
            "lines_of_code": loc,
            "num_functions": n_fn,
            "num_modifiers": n_mod,
            "has_transfer_function": has_transfer,
            "has_owner_control": has_owner,
            "has_blacklist_mapping": 0,
            "has_sell_restriction_logic": 0,
            "has_excessive_fee": 0,
            "has_unbounded_fee_setter": 0,
            "has_cooldown_delay": 0,
            "has_pausable_transfers": 0,
            "has_max_tx_wallet_limit": 0,
            "has_hidden_mint": 0,
            "has_inline_assembly": 0,
            "has_external_transfer_call": 0,
            "num_positive_indicators": num_pos,
            "has_openzeppelin_imports": oz,
            "has_renounce_ownership": ren,
            "num_total_findings": 0,
            "is_honeypot": 0,
        }
        rows.append(row)

    # Process Honeypot profiles
    for i, p in enumerate(HONEYPOT_PROFILES, 1):
        (
            name, origin, loc, n_fn, n_mod, has_transfer, has_owner,
            blk, sell_rst, exc_tax, unb_tax, cool, pause, max_lim, mint, asm, ext,
            num_pos, oz, ren
        ) = p

        findings_count = sum([blk, sell_rst, exc_tax, unb_tax, cool, pause, max_lim, mint, asm, ext])

        row = {
            "contract_id": f"HONEYPOT_{i:03d}",
            "contract_name": name,
            "source_origin": origin,
            "lines_of_code": loc,
            "num_functions": n_fn,
            "num_modifiers": n_mod,
            "has_transfer_function": has_transfer,
            "has_owner_control": has_owner,
            "has_blacklist_mapping": blk,
            "has_sell_restriction_logic": sell_rst,
            "has_excessive_fee": exc_tax,
            "has_unbounded_fee_setter": unb_tax,
            "has_cooldown_delay": cool,
            "has_pausable_transfers": pause,
            "has_max_tx_wallet_limit": max_lim,
            "has_hidden_mint": mint,
            "has_inline_assembly": asm,
            "has_external_transfer_call": ext,
            "num_positive_indicators": num_pos,
            "has_openzeppelin_imports": oz,
            "has_renounce_ownership": ren,
            "num_total_findings": findings_count,
            "is_honeypot": 1,
        }
        rows.append(row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} records ({len(BENIGN_PROFILES)} benign, {len(HONEYPOT_PROFILES)} honeypot) -> {output_path}")


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "data" / "sample_contract_features.csv"
    generate_dataset_csv(out)
