pub use crate::*;

pub use subxt::{
    backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
    config::ExtrinsicParams,
    tx::{PartialExtrinsic, Payload, Signer, SubmittableExtrinsic},
    utils::Static,
    OnlineClient,
};

use tokio::time::{sleep, Duration};

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

/// Sign a native transaction.
pub async fn apply_native_signature_to_transaction<A, S>(
    partial_ext: &PartialExtrinsic<CentrumConfig, NativeClient>,
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
    client: &NativeClient,
    rpc: &NativeRpcClient,
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
    rpc: &NativeRpcClient,
    client: &NativeClient,
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
    client: &NativeClient,
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

pub async fn internal_request_mpc_signature_payload(
    payload: [u8; 32],
    client: &NativeClient,
    rpc: &NativeRpcClient,
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
