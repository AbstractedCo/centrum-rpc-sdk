use ethers::prelude::abigen;

pub const ETH_SEPOLIA_BASE_STANDARD_BRIDGE_ADDRESS: &str =
    "0xfd0Bf71F60660E2f608ed56e1659C450eB113120";
pub const ETH_MAINNET_BASE_STANDARD_BRIDGE_ADDRESS: &str =
    "0x3154Cf16ccdb4C6d922629664174b904d80F2C35";
pub const ETH_SEPOLIA_UNISWAP_V2_FACTORY: &str = "0xF62c03E08ada871A0bEb309762E260a7a6a880E6";
pub const ETH_SEPOLIA_UNISWAP_V2_ROUTER: &str = "0xeE567Fe1712Faf6149d80dA1E6934E354124CfE3";
pub const ETH_MAINNET_UNISWAP_V2_FACTORY: &str = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f";
pub const ETH_MAINNET_UNISWAP_V2_ROUTER: &str = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
pub const WETH_MAINNET: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
pub const WETH_SEPOLIA: &str = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14";
pub const UNI_SEPOLIA: &str = "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984";
pub const PHA_MAINNET: &str = "0x6c5bA91642F10282b576d91922Ae6448C9d52f4E";
pub const AVALANCHE_LIQUID_STAKE_TESTNET: &str = "0x0c29d40cbd3c9073f4c0c96bf88ae1b4b4fe1d11";
pub const AVALANCHE_LIQUID_STAKE_MAINNET: &str = "0x7BAa1E3bFe49db8361680785182B80BB420A836D";

abigen!(
    ERC20,
    r#"[
      {
        "constant": true,
        "inputs": [
          {
            "name": "account",
            "type": "address"
          }
        ],
        "name": "balanceOf",
        "outputs": [
          {
            "name": "",
            "type": "uint256"
          }
        ],
        "type": "function"
      }
    ]"#
);

abigen!(
    L1StandardBridge,
    r#"[
    {
        "inputs": [
            {
                "internalType": "uint32",
                "name": "_minGasLimit",
                "type": "uint32"
            },
            {
                "internalType": "bytes",
                "name": "_extraData",
                "type": "bytes"
            }
        ],
        "name": "depositETH",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    }
]"#
);

abigen!(
    UniswapV2Router02,
    r#"[
    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "amountOutMin",
                "type": "uint256"
            },
            {
                "internalType": "address[]",
                "name": "path",
                "type": "address[]"
            },
            {
                "internalType": "address",
                "name": "to",
                "type": "address"
            },
            {
                "internalType": "uint256",
                "name": "deadline",
                "type": "uint256"
            }
        ],
        "name": "swapExactETHForTokens",
        "outputs": [
            {
                "internalType": "uint256[]",
                "name": "amounts",
                "type": "uint256[]"
            }
        ],
        "stateMutability": "payable",
        "type": "function"
    },
        {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "amountIn",
                "type": "uint256"
            },
            {
                "internalType": "address[]",
                "name": "path",
                "type": "address[]"
            }
        ],
        "name": "getAmountsOut",
        "outputs": [
            {
                "internalType": "uint256[]",
                "name": "amounts",
                "type": "uint256[]"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }]"#
);

abigen!(
    AvaxLiquidStakingANKR,
    r#"[
    {
        "inputs": [],
        "name": "stakeAndClaimCerts",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "amount",
                "type": "uint256"
            }
        ],
        "name": "claimCerts",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]"#
);
