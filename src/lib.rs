#![cfg_attr(not(feature = "std"), no_std)]

// use frame_metadata::RuntimeMetadataPrefixed;
use codec::Encode;
use sp_std::{str::FromStr, sync::Arc};
use std::collections::HashMap;

#[cfg(not(test))]
use log::{info, warn}; // Use log crate when building application

#[cfg(all(test, feature = "console_log_dep"))]
use log::{info, warn}; // Use log crate when building application

#[cfg(all(test, not(feature = "console_log_dep")))]
use std::{println as info, println as warn}; // Workaround to use prinltn! for logs

use bitcoin::CompressedPublicKey;
use elliptic_curve::sec1::ToEncodedPoint;

use ethers::{
    abi::Address as ContractAddress,
    middleware::{MiddlewareBuilder, NonceManagerMiddleware},
    prelude::{Http, Provider as EvmProvider},
    providers::Middleware,
    types::{
        transaction::eip2718::TypedTransaction, NameOrAddress, TransactionReceipt,
        TransactionRequest, U256,
    },
};
use hyperliquid_rust_sdk::{BaseUrl, ExchangeClient, InfoClient, MarketOrderParams};
use rlp::Decodable;
use subxt::{
    backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
    config::ExtrinsicParams,
    tx::{PartialExtrinsic, Payload, Signer, SubmittableExtrinsic},
    utils::Static,
    OnlineClient,
};

use subxt_signer::SecretUri;

use tokio::time::{sleep, Duration};

use wasm_bindgen::prelude::*;
// use wasm_bindgen_futures::wasm_bindgen::convert::IntoWasmAbi;

pub mod centrum_config;
pub mod error;
#[allow(unused_imports)]
pub mod utils;

pub use utils::*;

pub use centrum_config::*;
use contract_utils::{
    L1StandardBridge, UniswapV2Router02, ETH_MAINNET_UNISWAP_V2_ROUTER,
    ETH_SEPOLIA_BASE_STANDARD_BRIDGE_ADDRESS, ETH_SEPOLIA_UNISWAP_V2_ROUTER, PHA_MAINNET,
    UNI_SEPOLIA, WETH_MAINNET, WETH_SEPOLIA,
};
pub use error::Error;
#[allow(unused_imports)]
use signature_utils::{
    btc_sig_from_mpc_sig, eth_sign_transaction, testnet_btc_address, EthRecipt, PublicKey,
    HUNDRED_SATS,
};

#[allow(dead_code, unused_imports)]
mod tests;

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
pub type EvmClient = NonceManagerMiddleware<EvmProvider<Http>>;

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

async fn start_rpc_client_from_url(url: &str) -> Result<RpcClient, subxt::Error> {
    RpcClient::from_url(url).await
}

async fn start_local_rpc_client() -> Result<RpcClient, subxt::Error> {
    if let Ok(rpc) = RpcClient::from_url("ws://127.0.0.1:9944").await {
        Ok(rpc)
    } else {
        Ok(RpcClient::from_url("ws://localhost:8000").await?)
    }
}

pub async fn start_client_from_url(url: &str) -> Result<CentrumClient, subxt::Error> {
    OnlineClient::<CentrumConfig>::from_rpc_client(start_rpc_client_from_url(url).await?).await
}

pub async fn start_local_client() -> Result<CentrumClient, subxt::Error> {
    OnlineClient::<CentrumConfig>::from_rpc_client(start_local_rpc_client().await?).await
}

pub async fn start_raw_local_rpc_client() -> Result<CentrumRpcClient, subxt::Error> {
    Ok(LegacyRpcMethods::<CentrumConfig>::new(
        start_local_rpc_client().await?,
    ))
}

pub async fn start_raw_rpc_client_from_url(url: &str) -> Result<CentrumRpcClient, subxt::Error> {
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
) -> Result<(), Error> {
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
            Err(Error::SubxtError(err))
        }
    }
}

/// Submits a signature request extrinsic and waits for the signature to be delivered.
pub async fn submit_mpc_signature_request(
    client: &CentrumClient,
    rpc: &CentrumRpcClient,
    ext: SubmittableExtrinsic<CentrumConfig, OnlineClient<CentrumConfig>>,
) -> Result<runtime::mpc_manager::events::SignatureDelivered, Error> {
    let result = ext.submit_and_watch().await?;

    let mut current_header = rpc.chain_get_header(None).await?.unwrap().number;

    info!("Submitted mpc signature request");

    info!("waiting for transaction to be included...");

    let res = result.wait_for_finalized_success().await?;
    info!("signature request submitted");

    let sig_request = res
        .find_first::<runtime::mpc_manager::events::SignatureRequested>()?
        .ok_or(Error::SubxtError(subxt::Error::Other(
            "signature request not found".to_string(),
        )))?;

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

    Err(Error::SubxtError(subxt::Error::Other(
        "signature not found".to_string(),
    )))
}

/// Creates a partial extrinsic with default params for offline signature.
pub async fn create_partial_extrinsic<A>(
    rpc: &CentrumRpcClient,
    client: &CentrumClient,
    account: A,
    payload: Box<dyn Payload>,
) -> Result<
    PartialExtrinsic<centrum_config::CentrumConfig, OnlineClient<centrum_config::CentrumConfig>>,
    subxt::Error,
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
pub async fn create_rmrk_payload() -> Result<Box<dyn Payload>, subxt::Error> {
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
) -> Result<PublicKey, Error> {
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
    eth_provider: Arc<EvmClient>,
    from: PublicKey,
    dest: &str,
    amount: Option<u128>,
) -> Result<TypedTransaction, Error> {
    let chain_id = eth_provider.get_chainid().await?.as_u64();

    let eth_nonce = eth_provider.next();

    let to = {
        if let Ok(addr) = NameOrAddress::from_str(dest) {
            addr
        } else {
            let addr = hex::decode("AD8A02c8D7E01C72228A027F9ccfbE9d78310ca9")?;
            let addr = <[u8; 20] as TryFrom<Vec<u8>>>::try_from(addr.clone())
                .map_err(|_| Error::FailedToConvertPayloadTo20Bytes(addr))?;
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
    eth_provider: Arc<EvmClient>,
    from: PublicKey,
    _amount: Option<u128>,
) -> Result<TypedTransaction, Error> {
    let chain_id = eth_provider.get_chainid().await?.as_u64();
    let eth_nonce = eth_provider.next();

    let l1_bridge_addr: ContractAddress =
        ContractAddress::from_str(ETH_SEPOLIA_BASE_STANDARD_BRIDGE_ADDRESS)?;
    let bridge = L1StandardBridge::new(l1_bridge_addr, eth_provider.clone());

    let amount = _amount.unwrap_or(1_000_000_000_000_000u128);

    let extra_data: Vec<u8> = vec![]; // empty
    let min_gas_limit: u32 = 400_000;
    let call = bridge
        .deposit_eth(min_gas_limit, extra_data.into())
        .value(amount) // attach 0.01 ETH
        .gas(4_000_000u64); // example gas limit override

    let calldata = call
        .calldata()
        .ok_or(Error::Other("No calldata".to_string()))?;
    let to = call
        .tx
        .to()
        .ok_or(Error::Other("No to address".to_string()))?;
    let value = call
        .tx
        .value()
        .ok_or(Error::Other("No value".to_string()))?;
    let gas_limit = call
        .tx
        .gas()
        .ok_or(Error::Other("No gas limit".to_string()))?;

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
    router: &UniswapV2Router02<EvmClient>,
    amount: U256,
    path: Vec<ContractAddress>,
) -> Result<Vec<U256>, Error> {
    let call = router.get_amounts_out(amount, path).call().await?; // read-only call

    Ok(call)
}

pub async fn eth_uniswap_eth_for_token_payload(
    eth_provider: Arc<EvmClient>,
    from: PublicKey,
    _amount: Option<u128>,
    slippage_in_percent: u64,
    token_address: ContractAddress,
    testnet: bool,
) -> Result<TypedTransaction, Error> {
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
        .ok_or(Error::Other("No calldata".to_string()))?;
    let to = call
        .tx
        .to()
        .ok_or(Error::Other("No to address".to_string()))?;
    let value = call
        .tx
        .value()
        .ok_or(Error::Other("No value".to_string()))?;
    let gas_limit = call
        .tx
        .gas()
        .ok_or(Error::Other("No gas limit".to_string()))?;

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

pub async fn evm_sign_and_send_transaction(
    eth_provider: Arc<EvmClient>,
    eth_transaction: TypedTransaction,
    eth_signature: ethers::types::Signature,
) -> Result<TransactionReceipt, Error> {
    let signed_transaction = eth_transaction.rlp_signed(&eth_signature);

    info!("Submitting the transaction...");

    let pending = eth_provider
        .send_raw_transaction(signed_transaction.clone())
        .await?;

    info!("Pending: {:?}", pending);

    Ok(pending
        .await?
        .ok_or(Error::Other("failed to send eth transaction".to_string()))?)
}

pub async fn btc_create_transfer_payload(
    from: PublicKey,
    dest: &str,
    amount: Option<u64>,
) -> Result<BtcPayload, Error> {
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
        sighash: <[u8; 32]>::try_from(sig_hash.clone())
            .map_err(|_| Error::FailedToConvertPayloadTo32Bytes(sig_hash))?,
        unsigned_tx,
        compressed_public_key,
    })
}

pub async fn btc_sign_and_send_transaction(
    btc_payload: BtcPayload,
    mpc_sig: MpcSignatureDelivered,
) -> Result<String, Error> {
    let bitcoin_signature = btc_sig_from_mpc_sig(mpc_sig).signature.serialize_der();

    let hex_sig = hex::encode(bitcoin_signature.to_vec());

    let pubkey = hex::encode(btc_payload.compressed_public_key.to_bytes());

    let res = fillTxAndSubmit(btc_payload.unsigned_tx, hex_sig, pubkey).await;

    res.as_string()
        .ok_or(Error::Other("Failed to get tx hash".to_string()))
}

pub async fn internal_request_mpc_signature_payload(
    payload: [u8; 32],
    client: &CentrumClient,
    rpc: &CentrumRpcClient,
    signer: &CentrumMultiSigner,
) -> Result<MpcSignatureDelivered, Error> {
    let partial_ext = create_partial_extrinsic(
        rpc,
        client,
        signer.account_id(),
        request_mpc_signature_payload(payload).await,
    )
    .await?;

    let submittable = apply_native_signature_to_transaction(
        &partial_ext,
        signer.account_id(),
        demo_sign_native_with_signer(&partial_ext, signer).await,
    )
    .await;

    let delivered = submit_mpc_signature_request(client, rpc, submittable).await?;
    Ok(MpcSignatureDelivered {
        payload: delivered.payload.to_vec(),
        epsilon: delivered.epsilon.to_vec(),
        big_r: delivered.big_r,
        s: delivered.s,
    })
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

#[derive(Debug, Clone)]
pub struct HyperLiquidClient {
    pub info_client: Arc<InfoClient>,
    pub exchange_client: Arc<ExchangeClient>,
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Demo {
    #[wasm_bindgen(skip)]
    pub client: CentrumClient,
    #[wasm_bindgen(skip)]
    pub rpc: CentrumRpcClient,
    #[wasm_bindgen(skip)]
    pub eth_client: Arc<EvmClient>,
    #[wasm_bindgen(skip)]
    pub avax_p_client: Arc<EvmClient>,
    #[wasm_bindgen(skip)]
    pub hyperliquid_client: HyperLiquidClient,
    #[wasm_bindgen(skip)]
    pub custom_clients_map: HashMap<String, Arc<EvmClient>>,
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
            EvmClient,
            EvmClient,
            HyperLiquidClient,
            PublicKey,
            CompressedPublicKey,
        ),
        Error,
    > {
        #[cfg(all(debug_assertions, feature = "console_log_dep"))]
        console_log::init_with_level(log::Level::Debug)?;
        let client = start_client_from_url(centrum_node_url).await?;
        let rpc = start_raw_rpc_client_from_url(centrum_node_url).await?;

        let signer_mpc_public_key = request_mpc_derived_account(
            &client,
            CentrumAccountId::PublicKey(signer.0.public_key().0.into()),
        )
        .await?;

        let encoded_point_compressed = signer_mpc_public_key
            .clone()
            .into_affine()
            .to_encoded_point(true);

        let compressed_public_key =
            CompressedPublicKey::from_slice(encoded_point_compressed.as_bytes()).unwrap();

        let eth_client = if eth_testnet {
            EvmProvider::<Http>::try_from("https://ethereum-sepolia-rpc.publicnode.com")
                .map_err(|_| Error::Other("failed to create rpc client".to_string()))?
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address())
        } else {
            EvmProvider::<Http>::try_from("https://ethereum-rpc.publicnode.com")
                .map_err(|_| Error::Other("failed to create rpc client".to_string()))?
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address())
        };
        eth_client.initialize_nonce(None).await?;

        let avax_p_client = if eth_testnet {
            EvmProvider::<Http>::try_from("https://avalanche-fuji-p-chain-rpc.publicnode.com")
                .map_err(|_| Error::Other("failed to create rpc client".to_string()))?
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address())
        } else {
            EvmProvider::<Http>::try_from("https://avalanche-p-chain-rpc.publicnode.com")
                .map_err(|_| Error::Other("failed to create rpc client".to_string()))?
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address())
        };
        // avax_p_client.initialize_nonce(None).await?;

        let hyperliquid_client = if eth_testnet {
            HyperLiquidClient {
                info_client: Arc::new(InfoClient::new(None, Some(BaseUrl::Testnet)).await?),
                exchange_client: Arc::new(
                    ExchangeClient::new(None, None, Some(BaseUrl::Testnet), None, None).await?,
                ),
            }
        } else {
            HyperLiquidClient {
                info_client: Arc::new(InfoClient::new(None, Some(BaseUrl::Mainnet)).await?),
                exchange_client: Arc::new(
                    ExchangeClient::new(None, None, Some(BaseUrl::Mainnet), None, None).await?,
                ),
            }
        };

        Ok((
            rpc,
            client,
            eth_client,
            avax_p_client,
            hyperliquid_client,
            signer_mpc_public_key,
            compressed_public_key,
        ))
    }

    #[wasm_bindgen(constructor)]
    pub async fn new_alice(centrum_node_url: &str, eth_testnet: bool) -> Result<Demo, Error> {
        #[cfg(all(debug_assertions, feature = "console_log_dep"))]
        console_log::init_with_level(log::Level::Debug)?;

        let signer = csigner();
        let (
            rpc,
            client,
            eth_client,
            avax_p_client,
            hyperliquid_client,
            signer_mpc_public_key,
            compressed_public_key,
        ) = Demo::create_clients(signer.clone(), centrum_node_url, eth_testnet).await?;

        Ok(Demo {
            client,
            rpc,
            eth_client: Arc::new(eth_client),
            avax_p_client: Arc::new(avax_p_client),
            hyperliquid_client,
            signer: signer.clone(),
            signer_mpc_public_key,
            compressed_public_key,
            custom_clients_map: HashMap::new(),
        })
    }

    pub async fn new_from_phrase(
        centrum_node_url: &str,
        seed_phrase: &str,
        eth_testnet: bool,
    ) -> Result<Demo, Error> {
        #[cfg(all(debug_assertions, feature = "console_log_dep"))]
        console_log::init_with_level(log::Level::Debug)?;
        let uri = SecretUri::from_str(seed_phrase).map_err(|e| Error::Other(e.to_string()))?;
        let signer: CentrumMultiSigner = subxt_signer::sr25519::Keypair::from_uri(&uri)
            .map_err(|e| Error::Other(e.to_string()))?
            .into();

        let (
            rpc,
            client,
            eth_client,
            avax_p_client,
            hyperliquid_client,
            signer_mpc_public_key,
            compressed_public_key,
        ) = Demo::create_clients(signer.clone(), centrum_node_url, eth_testnet).await?;

        Ok(Demo {
            client,
            rpc,
            eth_client: Arc::new(eth_client),
            avax_p_client: Arc::new(avax_p_client),
            hyperliquid_client,
            signer: signer.clone(),
            signer_mpc_public_key,
            compressed_public_key,
            custom_clients_map: HashMap::new(),
        })
    }

    /// Payload has to be [u8; 32]
    pub async fn request_mpc_signature_for_generic_payload(
        &self,
        payload: Vec<u8>,
    ) -> Result<MpcSignatureDelivered, Error> {
        let payload: [u8; 32] = payload
            .clone()
            .try_into()
            .map_err(|_| Error::FailedToConvertPayloadTo32Bytes(payload))?;

        internal_request_mpc_signature_payload(payload, &self.client, &self.rpc, &self.signer).await
    }

    async fn sign_and_submit_eth_transaction(
        &self,
        eth_payload: TypedTransaction,
    ) -> Result<EthRecipt, Error> {
        let eth_sighash = eth_payload.sighash();

        let mpc_signature = self
            .request_mpc_signature_for_generic_payload(eth_payload.sighash().0.to_vec())
            .await?;

        let eth_signature = eth_sign_transaction(
            eth_sighash,
            self.eth_client.get_chainid().await?.as_u64(),
            mpc_signature,
            self.signer_mpc_public_key.clone(),
        )?;

        info!("Eth signature created");

        let recipt = EthRecipt::from(
            evm_sign_and_send_transaction(self.eth_client.clone(), eth_payload, eth_signature)
                .await?,
        );

        info!("Submitted eth transaction",);

        Ok(recipt)
    }

    pub async fn submit_eth_sepolia_transfer(
        &self,
        dest: String,
        _amount: Option<u128>,
    ) -> Result<EthRecipt, Error> {
        let client_eth = self.eth_client.clone();

        let eth_payload = eth_sepolia_create_transfer_payload(
            client_eth,
            self.signer_mpc_public_key.clone(),
            &dest,
            _amount,
        )
        .await?;

        info!("Payload created");

        self.sign_and_submit_eth_transaction(eth_payload).await
    }

    pub async fn submit_eth_sepolia_bridge_to_base(
        &self,
        _amount: Option<u128>,
    ) -> Result<EthRecipt, Error> {
        let eth_payload = eth_sepolia_bridge_to_base_payload(
            self.eth_client.clone(),
            self.signer_mpc_public_key.clone(),
            _amount,
        )
        .await?;

        info!("ETH Sepolia bridge to base payload created");

        self.sign_and_submit_eth_transaction(eth_payload).await
    }

    pub async fn submit_eth_sepolia_swap_weth_for_uni(
        &self,
        _amount: Option<u128>,
    ) -> Result<EthRecipt, Error> {
        let eth_payload = eth_uniswap_eth_for_token_payload(
            self.eth_client.clone(),
            self.signer_mpc_public_key.clone(),
            _amount,
            1,
            ContractAddress::from_str(UNI_SEPOLIA)?,
            true,
        )
        .await?;

        info!("swap payload created");

        let recipt = self.sign_and_submit_eth_transaction(eth_payload).await?;

        info!("Swapped eth for token UNI",);

        Ok(recipt)
    }

    pub async fn submit_eth_mainnet_swap_eth_for_pha(
        &self,
        amount: Option<u128>,
    ) -> Result<EthRecipt, Error> {
        let eth_payload = eth_uniswap_eth_for_token_payload(
            self.eth_client.clone(),
            self.signer_mpc_public_key.clone(),
            amount,
            1,
            ContractAddress::from_str(PHA_MAINNET)?,
            false,
        )
        .await?;

        self.sign_and_submit_eth_transaction(eth_payload).await
    }

    pub async fn submit_btc_transfer(
        &self,
        dest: String,
        _amount: Option<u64>,
    ) -> Result<String, Error> {
        let btc_payload =
            btc_create_transfer_payload(self.signer_mpc_public_key.clone(), &dest, _amount).await?;

        let mpc_signature = self
            .request_mpc_signature_for_generic_payload(btc_payload.sighash.to_vec())
            .await?;

        Ok(btc_sign_and_send_transaction(btc_payload, mpc_signature).await?)
    }

    /// Places a market order on Hyperliquid, asset is the token symbol,
    /// like ETH, HYPE, etc.
    /// is_buy is true for buying, false for selling
    /// slippage is in percentage 0.1 = 10%
    pub async fn hyperliquid_market_order(
        &self,
        asset: String,
        is_buy: bool,
        amount: f64,
        slippage: f64,
    ) -> Result<String, Error> {
        let hyperliquid_client = &self.hyperliquid_client.exchange_client.clone();

        let (payload, hash, nonce) = hyperliquid_client
            .market_open_payload(MarketOrderParams {
                asset: asset.as_str(),
                is_buy,
                px: None,
                sz: amount,
                slippage: Some(slippage),
                cloid: None,
                wallet: None,
            })
            .await?;

        let mpc_signature = self
            .request_mpc_signature_for_generic_payload(hash.0.to_vec())
            .await?;

        let eth_signature = eth_sign_transaction(
            hash.clone(),
            27,
            mpc_signature,
            self.signer_mpc_public_key.clone(),
        )?;

        let recipt = hyperliquid_client
            .post(payload, eth_signature, nonce)
            .await?;

        info!("Hyperliquid market buy hype recipt: {:?}", recipt);

        Ok("Market order placed".to_string())
    }

    pub async fn add_custom_client(&mut self, name: String, url: String) -> Result<(), Error> {
        let provider = EvmProvider::<Http>::try_from(url)
            .map_err(|e| Error::Other(e.to_string()))?
            .nonce_manager(self.signer_mpc_public_key.clone().to_eth_address());
        provider.initialize_nonce(None).await?;
        self.custom_clients_map.insert(name, Arc::new(provider));
        Ok(())
    }

    pub async fn list_custom_clients(&self) -> Vec<String> {
        self.custom_clients_map.keys().cloned().collect()
    }

    /// Accepts a hex encoded transaction
    ///
    /// how it decodes to a Typed Transaction:
    /// uses hex::decode on the input
    /// rlp::Rlp::new on the result
    /// Decodes the rlp into a TypedTransaction
    pub async fn sign_and_submit_payload_to_custom_client(
        &self,
        client_name: String,
        tx_hex: String,
    ) -> Result<EthRecipt, Error> {
        let evm_client = self
            .custom_clients_map
            .get(&client_name)
            .ok_or(Error::Other("Client not found".to_string()))?;

        let typed_tx_hex = hex::decode(tx_hex)?;
        let tx_rlp = rlp::Rlp::new(typed_tx_hex.as_slice());
        let eth_payload = TypedTransaction::decode(&tx_rlp)?;

        let eth_sighash = eth_payload.sighash();

        let mpc_signature = internal_request_mpc_signature_payload(
            eth_sighash.0.clone(),
            &self.client,
            &self.rpc,
            &self.signer,
        )
        .await?;

        let eth_signature = eth_sign_transaction(
            eth_sighash,
            evm_client.get_chainid().await?.as_u64(),
            mpc_signature,
            self.signer_mpc_public_key.clone(),
        )?;

        info!("EVM signature created");

        let recipt = EthRecipt::from(
            evm_sign_and_send_transaction(evm_client.clone(), eth_payload, eth_signature).await?,
        );

        info!("Submitted EVM transaction",);

        Ok(recipt)
    }

    pub async fn query_custom_client_nonce(&self, client_name: String) -> Result<u64, Error> {
        let evm_client = self
            .custom_clients_map
            .get(&client_name)
            .ok_or(Error::Other("Client not found".to_string()))?;

        let nonce = evm_client.next().as_u64();

        Ok(nonce)
    }

    pub async fn query_custom_client_balance(&self, client_name: String) -> Result<String, Error> {
        let evm_client = self
            .custom_clients_map
            .get(&client_name)
            .ok_or(Error::Other("Client not found".to_string()))?;

        let bal = evm_client
            .get_balance(self.signer_mpc_public_key.clone().to_eth_address(), None)
            .await?;

        Ok(bal.to_string())
    }

    pub async fn query_hyperliquid_balances(&self) -> Result<String, Error> {
        let bal = self
            .hyperliquid_client
            .info_client
            .user_token_balances(self.signer_mpc_public_key.clone().to_eth_address())
            .await?;

        Ok(format!("{:?}", bal.balances))
    }

    pub async fn query_hyperliquid_recent_orders(&self) -> Result<String, Error> {
        let order = self
            .hyperliquid_client
            .info_client
            .historical_orders(self.signer_mpc_public_key.clone().to_eth_address())
            .await?;

        Ok(format!("{:?}", order))
    }

    pub async fn query_hyperliquid_orders(&self) -> Result<String, Error> {
        let order = self
            .hyperliquid_client
            .info_client
            .open_orders(self.signer_mpc_public_key.clone().to_eth_address())
            .await?;

        Ok(format!("{:?}", order))
    }

    pub async fn query_eth_balance(&self) -> Result<String, Error> {
        let bal = self
            .eth_client
            .get_balance(self.signer_mpc_public_key.clone().to_eth_address(), None)
            .await?;

        Ok(bal.to_string())
    }

    pub async fn query_btc_balance(&self) -> Result<String, Error> {
        let address = testnet_btc_address(self.compressed_public_key.clone());

        let balance: f64 = serde_wasm_bindgen::from_value(getBitcoinBalance(address).await)?;

        Ok(balance.to_string())
    }

    pub async fn query_native_balance(&self) -> Result<String, Error> {
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
