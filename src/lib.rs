#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use ethers::{middleware::signer, types::transaction::request};
use serde::{Deserialize, Serialize};
use subxt_core::runtime_api::payload;

// use frame_metadata::RuntimeMetadataPrefixed;
use core::{default::Default, ops::Deref};
use frame_metadata::RuntimeMetadataPrefixed;
use merkleized_metadata::ExtraInfo;
use scale_encode::EncodeAsType;
use sp_core::{blake2_256, Pair};
use sp_runtime::AccountId32;
use sp_std::{str::FromStr, sync::Arc};
use std::collections::HashMap;

#[cfg(not(test))]
use log::{info, warn}; // Use log crate when building application

#[cfg(all(test, feature = "console_log_dep"))]
use log::{info, warn}; // Use log crate when building application

#[cfg(all(test, not(feature = "console_log_dep")))]
use std::{println as info, println as warn}; // Workaround to use prinltn! for logs

use bitcoin::{
    amount, hashes::hash160::Hash, Address as BitcoinAddress, Amount, CompressedPublicKey, KnownHrp,
};
use elliptic_curve::{
    ops::Reduce,
    point::AffineCoordinates,
    scalar::FromUintUnchecked,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    CurveArithmetic,
};

use ethers::{
    abi::{Abi, Address as ContractAddress, JsonAbi},
    contract::{Contract, FunctionCall},
    middleware::{MiddlewareBuilder, NonceManagerMiddleware},
    prelude::{abigen, Http, Provider as EthProvider},
    providers::Middleware,
    types::{
        transaction::eip2718::TypedTransaction, NameOrAddress, Signature as EthersSignature,
        TransactionReceipt, TransactionRequest, U256,
    },
};

use subxt::{
    backend::{
        legacy::LegacyRpcMethods,
        rpc::{self, RpcClient},
    },
    client::{OfflineClientT, OnlineClientT},
    config::{
        substrate::MultiAddress::Address32, DefaultExtrinsicParamsBuilder, ExtrinsicParams, Header,
    },
    dynamic::{At, Value},
    ext,
    runtime_api::Payload as ApiPayload,
    tx::{PartialExtrinsic, Payload, Signer, SubmittableExtrinsic, ValidationResult},
    utils::{MultiAddress, MultiSignature, Static, H160},
    OnlineClient,
};

use subxt_signer::SecretUri;

use tokio::time::{sleep, Duration};

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::wasm_bindgen::convert::IntoWasmAbi;

pub mod centrum_config;
pub use centrum_config::*;
pub mod signature_utils;
use signature_utils::{
    btc_sig_from_mpc_sig, eth_sign_transaction, testnet_btc_address, EthRecipt, PublicKey,
    HUNDRED_SATS,
};
pub mod contract_utils;
use contract_utils::{
    ETH_MAINNET_UNISWAP_V2_ROUTER, ETH_SEPOLIA_BASE_STANDARD_BRIDGE_ADDRESS,
    ETH_SEPOLIA_UNISWAP_V2_ROUTER, PHA_MAINNET, UNI_SEPOLIA, WETH_MAINNET, WETH_SEPOLIA,
};

#[allow(dead_code)]
#[cfg(test)]
mod tests;
#[allow(dead_code)]
#[cfg(test)]
mod wasm_tests;

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

const _CHOPSTICKS_MOCK_SIGNATURE: [u8; 64] = [
    0xde, 0xad, 0xbe, 0xef, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
];

// const METADATA_PATH: &str = "artifacts/metadata-centrum.scale";

const _TOKEN_SYMBOL: &str = "Unit";

const PATH: &[u8] = b"test";

#[subxt::subxt(
    runtime_metadata_path = "artifacts/metadata-centrum.scale",
    derive_for_all_types = "Eq, PartialEq",
    substitute_type(
        path = "sp_runtime::multiaddress::MultiAddress<A, B>",
        with = "::subxt::utils::Static<sp_runtime::MultiAddress<A, B>>"
    ),
    substitute_type(
        path = "centrum_primitives::Account",
        with = "::subxt::utils::Static<centrum_primitives::Account>"
    )
)]
pub mod runtime {}

pub type CentrumClient = OnlineClient<CentrumConfig>;
pub type CentrumRpcClient = LegacyRpcMethods<CentrumConfig>;
pub type EthClient = NonceManagerMiddleware<EthProvider<Http>>;

#[wasm_bindgen(module = "/functions.js")]
extern "C" {
    #[wasm_bindgen]
    async fn buildTx(to: String, from: String, amount: String) -> JsValue;

    #[wasm_bindgen]
    async fn signPayloadPls(source: String, payload: JsValue) -> JsValue;

    #[wasm_bindgen]
    async fn buildUnsignedTransaction(from: String, to: String, amount: String) -> JsValue;

    #[wasm_bindgen]
    fn hashFromUnsignedTx(unsignedTx: JsValue) -> String;

    #[wasm_bindgen]
    async fn getBitcoinBalance(address: String) -> JsValue;

    #[wasm_bindgen]
    async fn fillTxAndSubmit(unsignedTx: JsValue, signature: String, pubkey: String) -> JsValue;
}

async fn start_rpc_client_from_url(url: &str) -> Result<RpcClient, subxt::error::Error> {
    RpcClient::from_url(url).await
}

async fn start_local_rpc_client() -> Result<RpcClient, subxt::error::Error> {
    if let Ok(rpc) = RpcClient::from_url("ws://127.0.0.1:9944").await {
        Ok(rpc)
    } else {
        Ok(RpcClient::from_url("ws://localhost:8000").await?)
    }
}

pub async fn start_client_from_url(url: &str) -> Result<CentrumClient, subxt::error::Error> {
    OnlineClient::<CentrumConfig>::from_rpc_client(start_rpc_client_from_url(url).await?).await
}

pub async fn start_local_client() -> Result<CentrumClient, subxt::error::Error> {
    OnlineClient::<CentrumConfig>::from_rpc_client(start_local_rpc_client().await?).await
}

pub async fn start_raw_local_rpc_client() -> Result<CentrumRpcClient, subxt::error::Error> {
    Ok(LegacyRpcMethods::<CentrumConfig>::new(
        start_local_rpc_client().await?,
    ))
}

pub async fn start_raw_rpc_client_from_url(
    url: &str,
) -> Result<CentrumRpcClient, subxt::error::Error> {
    Ok(LegacyRpcMethods::<CentrumConfig>::new(
        start_rpc_client_from_url(url).await?,
    ))
}

pub fn csigner() -> CentrumMultiSigner {
    subxt_signer::sr25519::dev::alice().into()
}

/// for the demo
pub async fn demo_sign_native_with_signer(
    partial: &PartialExtrinsic<
        centrum_config::CentrumConfig,
        OnlineClient<centrum_config::CentrumConfig>,
    >,
    signer: &CentrumMultiSigner,
) -> CentrumSignature {
    signer.sign(&partial.signer_payload())
}

/// Sign a native transaction.
pub async fn apply_native_signature_to_transaction<A, S>(
    partial_ext: &PartialExtrinsic<CentrumConfig, CentrumClient>,
    account: A,
    signature: S,
) -> SubmittableExtrinsic<CentrumConfig, OnlineClient<CentrumConfig>>
where
    A: Into<CentrumMultiAccount>,
    S: Into<CentrumMultiSignature>,
{
    partial_ext.sign_with_address_and_signature(
        &CentrumAddress::from(account.into()),
        &CentrumSignature::from(signature.into()),
    )
}

pub async fn submit_native_transaction(
    ext: SubmittableExtrinsic<CentrumConfig, OnlineClient<CentrumConfig>>,
) -> Result<(), subxt::error::Error> {
    let result = ext.submit_and_watch().await?;

    info!("submit native transaction result: {:?}", result);

    info!("waiting for transaction to be included...");

    match result.wait_for_finalized_success().await {
        Ok(_) => {
            info!("transaction finalized");
            Ok(())
        }
        Err(err) => {
            warn!("transaction error: {:?}", err);
            Err(err)
        }
    }
}

/// Submits a signature request extrinsic and waits for the signature to be delivered.
pub async fn submit_mpc_signature_request(
    client: &CentrumClient,
    rpc: &CentrumRpcClient,
    ext: SubmittableExtrinsic<CentrumConfig, OnlineClient<CentrumConfig>>,
) -> Result<runtime::mpc_manager::events::SignatureDelivered, subxt::error::Error> {
    let result = ext.submit_and_watch().await?;

    let mut current_header = rpc.chain_get_header(None).await?.unwrap().number;

    info!("Submitted mpc signature request");

    info!("waiting for transaction to be included...");

    let res = result.wait_for_finalized_success().await?;
    info!("signature request submitted");

    let sig_request = res
        .find_first::<runtime::mpc_manager::events::SignatureRequested>()?
        .ok_or(subxt::error::Error::Other(
            "signature request not found".to_string(),
        ))?;

    let _epsilon = sig_request.epsilon;

    // todo!(re-write this crap for the love of god)
    for _ in 1..=5 {
        current_header += 1;
        let bhash = {
            let mut _bhash = rpc
                .chain_get_block_hash(Some((current_header).into()))
                .await?;
            while let None = _bhash {
                sleep(Duration::from_millis(3000)).await;
                _bhash = rpc
                    .chain_get_block_hash(Some((current_header).into()))
                    .await?;
            }
            _bhash.unwrap()
        };

        let _e = client.events().at(bhash).await?;

        let _ev: Vec<_> = _e
            .find::<runtime::mpc_manager::events::SignatureDelivered>()
            .filter_map(|e| e.ok())
            .collect();
        for e in _ev {
            if e.epsilon == _epsilon {
                info!("Signature delivered");
                // info!("Epsilon: {:?} \n big_r: {:?} \n payload: {:?} \n payload: {:?} \n delivered_by: {:?}", e.epsilon, e.s, e.big_r, e.payload, e.delivered_by);
            }
            return Ok(e);
        }
    }

    Err(subxt::error::Error::Other(
        "signature not found".to_string(),
    ))
}

/// Creates a partial extrinsic with default params for offline signature.
pub async fn create_partial_extrinsic<A>(
    rpc: &CentrumRpcClient,
    client: &CentrumClient,
    account: A,
    payload: Box<dyn Payload>,
) -> Result<
    PartialExtrinsic<centrum_config::CentrumConfig, OnlineClient<centrum_config::CentrumConfig>>,
    subxt::error::Error,
>
where
    A: Into<CentrumMultiAccount>,
{
    let current_nonce = rpc
        .system_account_next_index(&CentrumAccountId::from(account.into()))
        .await?;

    let params: <<CentrumConfig as subxt::Config>::ExtrinsicParams as ExtrinsicParams<
        CentrumConfig,
    >>::Params = SubstrateExtrinsicParamsBuilder::new()
        .nonce(current_nonce)
        .build();
    // client.storage().
    client.tx().create_partial_signed_offline(&payload, params)
}

/// todo!(Creates a partial extrinsic from a enum of possible extrinsics).
pub async fn create_rmrk_payload() -> Result<Box<dyn Payload>, subxt::error::Error> {
    Ok(Box::new(runtime::tx().system().remark(vec![0u8; 32])))
}

pub async fn request_mpc_signature_payload(payload: [u8; 32]) -> Box<dyn Payload> {
    Box::new(
        runtime::tx()
            .mpc_manager()
            .request_signature(payload, PATH.to_vec()),
    )
}

pub async fn request_mpc_derived_account(
    client: &CentrumClient,
    account: CentrumAccountId,
) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let values = (account, PATH).encode();

    let call_result: PublicKey = client
        .runtime_api()
        .at_latest()
        .await?
        .call_raw::<PublicKey>("MpcManagerApi_derive_account", Some(&values))
        .await?;

    Ok(call_result)
}

pub async fn eth_sepolia_create_transfer_payload(
    eth_provider: Arc<EthClient>,
    from: PublicKey,
    dest: &str,
    amount: Option<u128>,
) -> Result<TypedTransaction, Box<dyn std::error::Error>> {
    let chain_id = eth_provider.get_chainid().await?.as_u64();

    let eth_nonce = eth_provider.next();

    let to = {
        if let Ok(addr) = NameOrAddress::from_str(dest) {
            addr
        } else {
            let addr = hex::decode("AD8A02c8D7E01C72228A027F9ccfbE9d78310ca9")?;
            let addr = <[u8; 20] as TryFrom<Vec<u8>>>::try_from(addr)
                .map_err(|_| subxt::error::Error::Other("Invalid address".to_string()))?;
            NameOrAddress::Address(addr.into())
        }
    };

    let amount = amount.unwrap_or(100_000_000_000_000u128);

    let mut eth_transaction: TypedTransaction = TransactionRequest {
        from: Some(from.clone().to_eth_address()),
        to: Some(to),
        value: Some(amount.into()),
        nonce: Some(eth_nonce),
        chain_id: Some(chain_id.into()),
        gas: None,
        gas_price: None,
        data: None,
    }
    .into();

    eth_provider
        .fill_transaction(&mut eth_transaction, None)
        .await
        .unwrap();
    Ok(eth_transaction)
}

pub async fn eth_sepolia_bridge_to_base_payload(
    eth_provider: Arc<EthClient>,
    from: PublicKey,
    _amount: Option<u128>,
) -> Result<TypedTransaction, Box<dyn std::error::Error>> {
    let chain_id = eth_provider.get_chainid().await?.as_u64();
    let eth_nonce = eth_provider.next();

    let l1_bridge_addr: ContractAddress =
        ContractAddress::from_str(ETH_SEPOLIA_BASE_STANDARD_BRIDGE_ADDRESS)?;
    let bridge = L1StandardBridge::new(l1_bridge_addr, eth_provider.clone());

    let amount = _amount.unwrap_or(1_000_000_000_000_000u128);

    let extra_data: Vec<u8> = vec![]; // empty
    let min_gas_limit: u32 = 200_000;
    let call = bridge
        .deposit_eth(min_gas_limit, extra_data.into())
        .value(amount) // attach 0.01 ETH
        .gas(1_000_000u64); // example gas limit override

    let calldata = call
        .calldata()
        .ok_or(subxt::Error::Other("No calldata".to_string()))?;
    let to = call
        .tx
        .to()
        .ok_or(subxt::Error::Other("No to address".to_string()))?;
    let value = call
        .tx
        .value()
        .ok_or(subxt::Error::Other("No value".to_string()))?;
    let gas_limit = call
        .tx
        .gas()
        .ok_or(subxt::Error::Other("No gas limit".to_string()))?;

    let from_addr = from.clone().to_eth_address();
    let gas_price = eth_provider.get_gas_price().await?;

    let mut eth_transaction: TypedTransaction = TransactionRequest {
        from: Some(from_addr),
        to: Some(to.clone()),
        value: Some(value.clone()),
        nonce: Some(eth_nonce),
        chain_id: Some(chain_id.into()),
        gas: Some(gas_limit.clone()),
        gas_price: Some(gas_price),
        data: Some(calldata),
    }
    .into();

    eth_provider
        .fill_transaction(&mut eth_transaction, None)
        .await?;

    Ok(eth_transaction)
}

pub async fn eth_get_uniswap_amounts_out(
    router: &UniswapV2Router02<EthClient>,
    amount: U256,
    path: Vec<ContractAddress>,
) -> Result<Vec<U256>, Box<dyn std::error::Error>> {
    let call = router.get_amounts_out(amount, path).call().await?; // read-only call

    Ok(call)
}

pub async fn eth_uniswap_eth_for_token_payload(
    eth_provider: Arc<EthClient>,
    from: PublicKey,
    _amount: Option<u128>,
    slippage_in_percent: u64,
    token_address: ContractAddress,
    testnet: bool,
) -> Result<TypedTransaction, Box<dyn std::error::Error>> {
    let chain_id = eth_provider.get_chainid().await?.as_u64();
    let eth_nonce = eth_provider.next();

    let amount = U256::from(_amount.unwrap_or(1_000_000_000_000_000u128));

    let router_address: ContractAddress = if testnet {
        ContractAddress::from_str(ETH_SEPOLIA_UNISWAP_V2_ROUTER)?
    } else {
        ContractAddress::from_str(ETH_MAINNET_UNISWAP_V2_ROUTER)?
    };
    let router = UniswapV2Router02::new(router_address, eth_provider.clone());

    let weth = if testnet {
        ContractAddress::from_str(WETH_SEPOLIA)?
    } else {
        ContractAddress::from_str(WETH_MAINNET)?
    };

    let path = vec![weth, token_address];

    let estimated_out = eth_get_uniswap_amounts_out(&router, amount, path.clone()).await?;
    let deadline = U256::from(chrono::Utc::now().timestamp() + 60); // 60 secs from now

    let estimated_out = estimated_out.last().unwrap();

    // 100% == 10_000 BIPS.
    let one_hundred_percent = U256::from(10_000u64);

    let slippage_bps = U256::from(slippage_in_percent * 100u64);

    let min_out = (estimated_out * (one_hundred_percent - slippage_bps)) / one_hundred_percent;

    info!(
        "Swapping {:?} ETH for {:?}, Slippage: {}%",
        amount, min_out, slippage_in_percent
    );

    let call = router
        .swap_exact_eth_for_tokens(min_out, path, from.clone().to_eth_address(), deadline)
        .value(amount)
        .gas(1_000_000u64);

    let calldata = call
        .calldata()
        .ok_or(subxt::Error::Other("No calldata".to_string()))?;
    let to = call
        .tx
        .to()
        .ok_or(subxt::Error::Other("No to address".to_string()))?;
    let value = call
        .tx
        .value()
        .ok_or(subxt::Error::Other("No value".to_string()))?;
    let gas_limit = call
        .tx
        .gas()
        .ok_or(subxt::Error::Other("No gas limit".to_string()))?;

    let from_addr = from.clone().to_eth_address();
    let gas_price = eth_provider.get_gas_price().await?;

    let mut eth_transaction: TypedTransaction = TransactionRequest {
        from: Some(from_addr),
        to: Some(to.clone()),
        value: Some(value.clone()),
        nonce: Some(eth_nonce),
        chain_id: Some(chain_id.into()),
        gas: Some(gas_limit.clone()),
        gas_price: Some(gas_price),
        data: Some(calldata),
    }
    .into();

    eth_provider
        .fill_transaction(&mut eth_transaction, None)
        .await?;

    Ok(eth_transaction)
}

pub async fn eth_sepolia_sign_and_send_transaction(
    eth_provider: Arc<EthClient>,
    eth_transaction: TypedTransaction,
    eth_signature: ethers::types::Signature,
) -> Result<TransactionReceipt, Box<dyn std::error::Error>> {
    let signed_transaction = eth_transaction.rlp_signed(&eth_signature);

    Ok(eth_provider
        .send_raw_transaction(signed_transaction)
        .await?
        .await?
        .ok_or(subxt::error::Error::Other(
            "failed to send eth transaction".to_string(),
        ))?)
}

pub async fn btc_create_transfer_payload(
    from: PublicKey,
    dest: &str,
    amount: Option<u64>,
) -> Result<BtcPayload, Box<dyn std::error::Error>> {
    let encoded_point_compressed = from.into_affine().to_encoded_point(true);

    let compressed_public_key =
        CompressedPublicKey::from_slice(encoded_point_compressed.as_bytes()).unwrap();

    let from = testnet_btc_address(compressed_public_key);

    let amount = bitcoin::Amount::from_sat(amount.unwrap_or(100));

    let unsigned_tx = buildUnsignedTransaction(
        from,
        dest.to_string(),
        // String::from("CFqoZmZ3ePwK5wnkhxJjJAQKJ82C7RJdmd"),
        amount.to_sat().to_string(),
    )
    .await;

    let sig_hash = hex::decode(hashFromUnsignedTx(unsigned_tx.clone()).replace("0x", "")).unwrap();

    Ok(BtcPayload {
        sighash: <[u8; 32]>::try_from(sig_hash)
            .map_err(|_| subxt::error::Error::Other("Failed to convert to [u8; 32]".to_string()))?,
        unsigned_tx,
        compressed_public_key,
    })
}

pub async fn btc_sign_and_send_transaction(
    btc_payload: BtcPayload,
    mpc_sig: MpcSignatureDelivered,
) -> Result<String, JsError> {
    let bitcoin_signature = btc_sig_from_mpc_sig(mpc_sig).signature.serialize_der();

    let hex_sig = hex::encode(bitcoin_signature.to_vec());

    let pubkey = hex::encode(btc_payload.compressed_public_key.to_bytes());

    let res = fillTxAndSubmit(btc_payload.unsigned_tx, hex_sig, pubkey).await;

    res.as_string().ok_or(JsError::new("Failed to get tx hash"))
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone)]
pub struct MpcSignatureDelivered {
    /// [u8; 32]
    pub payload: Vec<u8>,
    /// [u8; 32]
    pub epsilon: Vec<u8>,
    pub big_r: Vec<u8>,
    pub s: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BtcPayload {
    pub unsigned_tx: JsValue,
    pub compressed_public_key: CompressedPublicKey,
    pub sighash: [u8; 32],
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Demo {
    #[wasm_bindgen(skip)]
    pub client: CentrumClient,
    #[wasm_bindgen(skip)]
    pub rpc: CentrumRpcClient,
    #[wasm_bindgen(skip)]
    pub eth_client: Arc<EthClient>,
    #[wasm_bindgen(skip)]
    pub signer: CentrumMultiSigner,
    #[wasm_bindgen(getter_with_clone)]
    pub signer_mpc_public_key: PublicKey,
    #[wasm_bindgen(skip)]
    pub compressed_public_key: CompressedPublicKey,
}

#[wasm_bindgen]
impl Demo {
    async fn create_clients(
        signer: CentrumMultiSigner,
        centrum_node_url: &str,
        eth_testnet: bool,
    ) -> Result<
        (
            CentrumRpcClient,
            CentrumClient,
            EthClient,
            PublicKey,
            CompressedPublicKey,
        ),
        JsError,
    > {
        #[cfg(all(debug_assertions, feature = "console_log_dep"))]
        console_log::init_with_level(log::Level::Debug)?;
        let client = start_client_from_url(centrum_node_url).await?;
        let rpc = start_raw_rpc_client_from_url(centrum_node_url).await?;

        let signer_mpc_public_key = request_mpc_derived_account(
            &client,
            CentrumAccountId::PublicKey(signer.0.public_key().0.into()),
        )
        .await
        .map_err(|_| JsError::new("failed to derive MPC public key"))?;

        let encoded_point_compressed = signer_mpc_public_key
            .clone()
            .into_affine()
            .to_encoded_point(true);

        let compressed_public_key =
            CompressedPublicKey::from_slice(encoded_point_compressed.as_bytes()).unwrap();

        let eth_client = if eth_testnet {
            EthProvider::<Http>::try_from("https://ethereum-sepolia-rpc.publicnode.com")
                .unwrap()
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address())
        } else {
            EthProvider::<Http>::try_from("https://ethereum-rpc.publicnode.com")
                .unwrap()
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address())
        };
        eth_client.initialize_nonce(None).await?;
        Ok((
            rpc,
            client,
            eth_client,
            signer_mpc_public_key,
            compressed_public_key,
        ))
    }

    #[wasm_bindgen(constructor)]
    pub async fn new_alice(centrum_node_url: &str, eth_testnet: bool) -> Result<Demo, JsError> {
        #[cfg(all(debug_assertions, feature = "console_log_dep"))]
        console_log::init_with_level(log::Level::Debug)?;

        let signer = csigner();
        let (rpc, client, eth_client, signer_mpc_public_key, compressed_public_key) =
            Demo::create_clients(signer.clone(), centrum_node_url, eth_testnet).await?;

        Ok(Demo {
            client,
            rpc,
            eth_client: Arc::new(eth_client),
            signer: signer.clone(),
            signer_mpc_public_key,
            compressed_public_key,
        })
    }

    pub async fn new_from_phrase(
        centrum_node_url: &str,
        seed_phrase: &str,
        eth_testnet: bool,
    ) -> Result<Demo, JsError> {
        #[cfg(all(debug_assertions, feature = "console_log_dep"))]
        console_log::init_with_level(log::Level::Debug)?;
        let uri = SecretUri::from_str(seed_phrase)
            .map_err(|_| subxt::error::Error::Other("failed to parse seed phrase".to_string()))?;
        let signer: CentrumMultiSigner = subxt_signer::sr25519::Keypair::from_uri(&uri)
            .map_err(|_| {
                subxt::error::Error::Other("failed to create signer from phrase".to_string())
            })?
            .into();

        let (rpc, client, eth_client, signer_mpc_public_key, compressed_public_key) =
            Demo::create_clients(signer.clone(), centrum_node_url, eth_testnet).await?;

        Ok(Demo {
            client,
            rpc,
            eth_client: Arc::new(eth_client),
            signer: signer.clone(),
            signer_mpc_public_key,
            compressed_public_key,
        })
    }

    pub async fn request_mpc_signature_for_generic_payload(
        &self,
        payload: Vec<u8>,
    ) -> Result<MpcSignatureDelivered, JsError> {
        let payload: [u8; 32] = payload
            .try_into()
            .map_err(|_| JsError::new("Failed to convert payload to [u8; 32]"))?;
        let partial_ext = create_partial_extrinsic(
            &self.rpc,
            &self.client,
            self.signer.account_id(),
            request_mpc_signature_payload(payload).await,
        )
        .await?;

        let submittable = apply_native_signature_to_transaction(
            &partial_ext,
            self.signer.account_id(),
            demo_sign_native_with_signer(&partial_ext, &self.signer).await,
        )
        .await;

        let delivered = submit_mpc_signature_request(&self.client, &self.rpc, submittable).await?;
        Ok(MpcSignatureDelivered {
            payload: delivered.payload.to_vec(),
            epsilon: delivered.epsilon.to_vec(),
            big_r: delivered.big_r,
            s: delivered.s,
        })
    }

    async fn sign_and_submit_eth_transaction(
        &self,
        eth_payload: TypedTransaction,
    ) -> Result<EthRecipt, JsError> {
        let eth_sighash = eth_payload.sighash();

        let mpc_signature = self
            .request_mpc_signature_for_generic_payload(eth_payload.sighash().0.to_vec())
            .await?;

        let eth_signature = eth_sign_transaction(
            eth_sighash,
            self.eth_client
                .get_chainid()
                .await
                .map_err(|_| JsError::new("Failed to get chain id"))?
                .as_u64(),
            mpc_signature,
            self.signer_mpc_public_key.clone(),
        )
        .map_err(|_| JsError::new("Failed to sign transaction"))?;

        let recipt = EthRecipt::from(
            eth_sepolia_sign_and_send_transaction(
                self.eth_client.clone(),
                eth_payload,
                eth_signature,
            )
            .await
            .map_err(|_| JsError::new("Failed to send transaction"))?,
        );

        info!("Submitted eth transaction",);

        Ok(recipt)
    }

    pub async fn submit_eth_sepolia_transfer(
        &self,
        dest: String,
        _amount: Option<u128>,
    ) -> Result<EthRecipt, JsError> {
        let client_eth = self.eth_client.clone();

        let eth_payload = eth_sepolia_create_transfer_payload(
            client_eth,
            self.signer_mpc_public_key.clone(),
            &dest,
            _amount,
        )
        .await
        .map_err(|_| JsError::new("Failed to create transfer payload"))?;

        self.sign_and_submit_eth_transaction(eth_payload).await
    }

    pub async fn submit_eth_sepolia_bridge_to_base(
        &self,
        _amount: Option<u128>,
    ) -> Result<EthRecipt, JsError> {
        let eth_payload = eth_sepolia_bridge_to_base_payload(
            self.eth_client.clone(),
            self.signer_mpc_public_key.clone(),
            _amount,
        )
        .await
        .map_err(|e| {
            JsError::new(&format!(
                "Failed to create eth sepolia bridge payload: {}",
                e
            ))
        })?;

        self.sign_and_submit_eth_transaction(eth_payload).await
    }

    pub async fn submit_eth_sepolia_swap_weth_for_uni(
        &self,
        _amount: Option<u128>,
    ) -> Result<EthRecipt, JsError> {
        let eth_payload = eth_uniswap_eth_for_token_payload(
            self.eth_client.clone(),
            self.signer_mpc_public_key.clone(),
            _amount,
            1,
            ContractAddress::from_str(UNI_SEPOLIA)?,
            true,
        )
        .await
        .map_err(|e| {
            JsError::new(&format!(
                "Failed to create eth sepolia bridge payload: {}",
                e
            ))
        })?;

        info!("swap payload created");

        let recipt = self.sign_and_submit_eth_transaction(eth_payload).await?;

        info!("Swapped eth for token UNI",);

        Ok(recipt)
    }

    pub async fn submit_eth_mainnet_swap_eth_for_pha(
        &self,
        amount: Option<u128>,
    ) -> Result<EthRecipt, JsError> {
        let eth_payload = eth_uniswap_eth_for_token_payload(
            self.eth_client.clone(),
            self.signer_mpc_public_key.clone(),
            amount,
            1,
            ContractAddress::from_str(PHA_MAINNET)?,
            false,
        )
        .await
        .map_err(|e| {
            JsError::new(&format!(
                "Failed to create eth sepolia bridge payload: {}",
                e
            ))
        })?;

        self.sign_and_submit_eth_transaction(eth_payload).await
    }

    pub async fn submit_btc_transfer(
        &self,
        dest: String,
        _amount: Option<u64>,
    ) -> Result<String, JsError> {
        let btc_payload =
            btc_create_transfer_payload(self.signer_mpc_public_key.clone(), &dest, _amount)
                .await
                .map_err(|_| JsError::new("Failed to create transfer payload"))?;

        let mpc_signature = self
            .request_mpc_signature_for_generic_payload(btc_payload.sighash.to_vec())
            .await?;

        btc_sign_and_send_transaction(btc_payload, mpc_signature).await
    }

    pub async fn query_eth_balance(&self) -> Result<String, JsError> {
        let bal = self
            .eth_client
            .get_balance(self.signer_mpc_public_key.clone().to_eth_address(), None)
            .await?;

        Ok(bal.to_string())
    }

    pub async fn query_btc_balance(&self) -> Result<String, JsError> {
        let address = testnet_btc_address(self.compressed_public_key.clone());

        let balance: f64 = serde_wasm_bindgen::from_value(getBitcoinBalance(address).await)?;

        Ok(balance.to_string())
    }

    pub async fn query_native_balance(&self) -> Result<String, JsError> {
        let account_sys = runtime::storage()
            .system()
            .account(Static::from(self.signer.account_id()));

        let res = self
            .client
            .storage()
            .at_latest()
            .await?
            .fetch(&account_sys)
            .await?;

        if res.is_none() {
            return Ok("0".to_string());
        }

        let res = res.unwrap();

        Ok(res.data.free.to_string())
    }

    pub async fn get_native_address(&self) -> String {
        let account = self.signer.account_id();
        account.to_string()
    }

    pub async fn get_eth_address(&self) -> String {
        let address = self.signer_mpc_public_key.clone().to_eth_address();
        let full_hex = hex::encode(address.0);
        format!("0x{}", full_hex)
    }

    pub async fn get_btc_address(&self) -> String {
        testnet_btc_address(self.compressed_public_key.clone())
    }
}
