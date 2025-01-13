#![cfg_attr(not(feature = "std"), no_std)]

use bitcoincore_rpc::jsonrpc::client;
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

#[cfg(not(test))]
use log::{info, warn}; // Use log crate when building application

#[cfg(test)]
use std::{println as info, println as warn}; // Workaround to use prinltn! for logs

use ethers::{
    middleware::{MiddlewareBuilder, NonceManagerMiddleware},
    prelude::{Http, Provider as EthProvider},
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
use signature_utils::{eth_sign_transaction, PublicKey};

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

    info!("submit native transaction result: {:?}", result);

    info!("waiting for transaction to be included...");

    let res = result.wait_for_finalized_success().await?;
    info!("transaction finalized: {:?}", res);

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
                info!("found signature event: {:?}", e);
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

    let mut eth_transaction: TypedTransaction = TransactionRequest {
        from: Some(from.clone().to_eth_address()),
        to: Some(to),
        value: Some(100_000_000_000_000u128.into()),
        nonce: Some(eth_nonce),
        chain_id: Some(chain_id.into()),
        gas: None,
        gas_price: None,
        data: None,
    }
    .into();

    // eth_transaction.chain_id()

    eth_provider
        .fill_transaction(&mut eth_transaction, None)
        .await
        .unwrap();
    Ok(eth_transaction)
}

pub async fn eth_sepolia_sign_and_send_transaction(
    eth_provider: Arc<EthClient>,
    eth_transaction: TypedTransaction,
    eth_signature: ethers::types::Signature,
) -> Result<TransactionReceipt, subxt::error::Error> {
    let signed_transaction = eth_transaction.rlp_signed(&eth_signature);

    eth_provider
        .send_raw_transaction(signed_transaction)
        .await
        .unwrap()
        .await
        .unwrap()
        .ok_or(subxt::error::Error::Other(
            "failed to send eth transaction".to_string(),
        ))
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
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthRecipt(TransactionReceipt);

#[wasm_bindgen]
impl Demo {
    #[wasm_bindgen(constructor)]
    pub async fn new_alice(centrum_node_url: &str) -> Result<Demo, JsError> {
        let signer = csigner();
        let client = start_client_from_url(centrum_node_url).await?;
        let rpc = start_raw_rpc_client_from_url(centrum_node_url).await?;

        let signer_mpc_public_key = request_mpc_derived_account(
            &client,
            CentrumAccountId::PublicKey(signer.0.public_key().0.into()),
        )
        .await
        .map_err(|_| subxt::error::Error::Other("failed to derive MPC public key".to_string()))?;

        let eth_client =
            EthProvider::<Http>::try_from("https://ethereum-sepolia-rpc.publicnode.com")
                .unwrap()
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address());
        eth_client.initialize_nonce(None).await?;
        Ok(Demo {
            client,
            rpc,
            eth_client: Arc::new(eth_client),
            signer: signer.clone(),
            signer_mpc_public_key,
        })
    }

    pub async fn new_from_phrase(
        centrum_node_url: &str,
        seed_phrase: &str,
    ) -> Result<Demo, JsError> {
        let uri = SecretUri::from_str(seed_phrase)
            .map_err(|_| subxt::error::Error::Other("failed to parse seed phrase".to_string()))?;
        let signer: CentrumMultiSigner = subxt_signer::sr25519::Keypair::from_uri(&uri)
            .map_err(|_| {
                subxt::error::Error::Other("failed to create signer from phrase".to_string())
            })?
            .into();

        let client = start_client_from_url(centrum_node_url).await?;
        let rpc = start_raw_rpc_client_from_url(centrum_node_url).await?;

        let signer_mpc_public_key = request_mpc_derived_account(
            &client,
            CentrumAccountId::PublicKey(signer.0.public_key().0.into()),
        )
        .await
        .map_err(|_| subxt::error::Error::Other("failed to derive MPC public key".to_string()))?;

        let eth_client =
            EthProvider::<Http>::try_from("https://ethereum-sepolia-rpc.publicnode.com")
                .unwrap()
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address());
        eth_client.initialize_nonce(None).await?;

        Ok(Demo {
            client,
            rpc,
            eth_client: Arc::new(eth_client),
            signer: signer.clone(),
            signer_mpc_public_key,
        })
    }

    pub async fn request_mpc_signature(
        &self,
        payload: Vec<u8>,
    ) -> Result<MpcSignatureDelivered, JsError> {
        let payload: [u8; 32] = payload.try_into().map_err(|_| {
            subxt::error::Error::Other("failed to convert payload to [u8; 32]".to_string())
        })?;
        // payload.truncate(32);
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
            payload: payload.to_vec(),
            epsilon: delivered.epsilon.to_vec(),
            big_r: delivered.big_r.to_vec(),
            s: delivered.s.to_vec(),
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
            // amount,
        )
        .await
        .map_err(|_| JsError::new("Failed to create transfer payload"))?;

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

        Ok(EthRecipt(
            eth_sepolia_sign_and_send_transaction(
                self.eth_client.clone(),
                eth_payload,
                eth_signature,
            )
            .await
            .map_err(|_| JsError::new("Failed to send transaction"))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn alice_submit_request_mpc_signature_works() -> Result<(), subxt::error::Error> {
        let client = start_local_client().await?;
        let rpc = start_raw_local_rpc_client().await?;

        let alice_signer = csigner();

        let partial_ext = create_partial_extrinsic(
            &rpc,
            &client,
            alice_signer.account_id(),
            request_mpc_signature_payload([0; 32]).await,
        )
        .await?;

        let submittable = apply_native_signature_to_transaction(
            &partial_ext,
            alice_signer.account_id(),
            demo_sign_native_with_signer(&partial_ext, &alice_signer).await,
        )
        .await;

        submit_mpc_signature_request(&client, &rpc, submittable).await?;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn alice_submit_rpc_derive_account_works() -> Result<(), Box<dyn std::error::Error>> {
        let account = request_mpc_derived_account(
            &start_local_client().await?,
            CentrumMultiAccount::from(subxt_signer::sr25519::dev::alice().public_key().0).0,
        )
        .await;

        info!("Alice Account: {:?}", account);

        Ok(())
    }

    #[ignore]
    #[tokio::test(flavor = "current_thread")]
    async fn alice_submit_remark_works() -> Result<(), subxt::error::Error> {
        let client = start_local_client().await?;
        let rpc = start_raw_local_rpc_client().await?;

        let alice_signer = csigner();

        let partial_ext = create_partial_extrinsic(
            &rpc,
            &client,
            alice_signer.account_id(),
            create_rmrk_payload().await?,
        )
        .await?;

        let submittable = apply_native_signature_to_transaction(
            &partial_ext,
            alice_signer.account_id(),
            demo_sign_native_with_signer(&partial_ext, &alice_signer).await,
        )
        .await;

        submit_native_transaction(submittable).await
    }
}

// let api = start_local_client().await?;

// let _metadata: Vec<u8> = fs::read(METADATA_PATH)?;
// let runtime_metadata = RuntimeMetadataPrefixed::decode(&mut &_metadata[..]).map(|x| x.1)?;

// println!("Runtime metadata: {:?}", runtime_metadata);

// let alice_pair: centrum_config::CentrumMultiSigner = subxt_signer::sr25519::dev::alice().into();
// let bob_pair: centrum_config::CentrumMultiSigner = subxt_signer::sr25519::dev::bob().into();

// let alice_account: Static<centrum_primitives::Account> =
//     Static(alice_pair.clone().account_id());

// let bob_account: Static<centrum_primitives::Account> = Static(bob_pair.clone().account_id());

// let old_alice: centrum_primitives::Account = alice_pair.clone().account_id();

// let rmrk = api
//     .tx()
//     .sign_and_submit_then_watch_default(
//         &runtime::tx().system().remark(vec![0u8; 32]),
//         &alice_pair,
//     )
//     .await?
//     .wait_for_finalized_success()
//     .await?;

// println!("remark tx: {:?}", rmrk);

// let alice_account_sys = runtime::storage().system().account(alice_account);

// let result = api.storage().at_latest().await?.fetch(&query).await?;

// let value = result.unwrap();

// let _a = runtime::storage().system().account(&alice_account);
// let _b = runtime::storage().system().account(&bob_account);

// println!(
//     "Alice account data: {:?}",
//     api.storage().at_latest().await?.fetch(&_a).await?
// );

// println!(
//     "Bob account data: {:?}",
//     api.storage().at_latest().await?.fetch(&_b).await?
// );
