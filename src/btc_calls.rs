use crate::*;

pub use bitcoin::CompressedPublicKey;

#[derive(Debug, Clone)]
pub struct BtcPayload {
    pub unsigned_tx: JsValue,
    pub compressed_public_key: CompressedPublicKey,
    pub sighash: [u8; 32],
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
