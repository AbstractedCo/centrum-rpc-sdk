#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
use codec::{Decode, Encode};
use subxt::{config::ExtrinsicParams, tx::PartialExtrinsic};
// use frame_metadata::RuntimeMetadataPrefixed;
use core::{default::Default, ops::Deref};
use frame_metadata::RuntimeMetadataPrefixed;
use merkleized_metadata::ExtraInfo;
use scale_encode::EncodeAsType;
use sp_core::{blake2_256, crypto::SecretUri, Pair};
use sp_runtime::AccountId32;
use std::fs;
use std::str::FromStr;

#[cfg(not(test))]
use log::{info, warn}; // Use log crate when building application

#[cfg(test)]
use std::{println as info, println as warn}; // Workaround to use prinltn! for logs

#[allow(unused_imports)]
use subxt::{
    backend::{
        legacy::LegacyRpcMethods,
        rpc::{self, RpcClient},
    },
    client::{OfflineClientT, OnlineClientT},
    config::{substrate::MultiAddress::Address32, DefaultExtrinsicParamsBuilder},
    dynamic::{At, Value},
    // runtime_api::Payload,
    tx::{Payload, Signer, SubmittableExtrinsic, ValidationResult},
    utils::{MultiAddress, MultiSignature, Static},
    // utils::Accound32,
    OnlineClient,
};

// use subxt_signer::sr25519::dev;
pub mod centrum_config;
pub use centrum_config::*;

const _CHOPSTICKS_MOCK_SIGNATURE: [u8; 64] = [
    0xde, 0xad, 0xbe, 0xef, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
];

// const METADATA_PATH: &str = "artifacts/metadata-centrum.scale";

const _TOKEN_SYMBOL: &str = "UNIT";

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

pub async fn start_raw_local_rpc_client(
) -> Result<LegacyRpcMethods<CentrumConfig>, subxt::error::Error> {
    Ok(LegacyRpcMethods::<CentrumConfig>::new(
        start_local_rpc_client().await?,
    ))
}

pub async fn start_raw_rpc_client_from_url(
    url: &str,
) -> Result<LegacyRpcMethods<CentrumConfig>, subxt::error::Error> {
    Ok(LegacyRpcMethods::<CentrumConfig>::new(
        start_rpc_client_from_url(url).await?,
    ))
}

pub fn csigner() -> CentrumMultiSigner {
    subxt_signer::sr25519::dev::alice().into()
}

/// for the demo
pub async fn demo_sign_native_with_signer<S>(
    partial: &PartialExtrinsic<
        centrum_config::CentrumConfig,
        OnlineClient<centrum_config::CentrumConfig>,
    >,
    signer: S,
) -> CentrumSignature
where
    S: Signer<CentrumConfig>,
{
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
        Ok(res) => {
            info!("transaction finalized: {:?}", res);
            Ok(())
        }
        Err(err) => {
            warn!("transaction error: {:?}", err);
            Err(err)
        }
    }
}

/// Creates a partial extrinsic with default params for offline signature.
pub async fn create_partial_extrinsic<A>(
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
    let rpc = start_raw_local_rpc_client().await?;

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
pub async fn create_payload() -> Result<Box<dyn Payload>, Box<dyn std::error::Error>> {
    Ok(Box::new(runtime::tx().system().remark(vec![0u8; 32])))
}

// pub async fn request_mpc_signature

// pub async fn

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn main() -> Result<(), Box<dyn std::error::Error>> {
        let client = start_local_client().await?;

        let account = subxt_signer::sr25519::dev::alice().public_key().0;

        let partial_ext =
            create_partial_extrinsic(&client, account.clone(), create_payload().await?).await?;

        let submittable = apply_native_signature_to_transaction(
            &partial_ext,
            account,
            demo_sign_native_with_signer(&partial_ext, csigner()).await,
        )
        .await;

        submit_native_transaction(submittable).await?;

        assert!(false);

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

        Ok(())
    }
}
