// use crate::*;
use wasm_bindgen::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("SubxtError: {0}")]
    SubxtError(#[from] subxt::Error),
    #[error("EthersContractError: {0}")]
    EthersContractError(
        #[from]
        ethers::contract::ContractError<
            ethers::middleware::nonce_manager::NonceManagerMiddleware<
                ethers::providers::Provider<ethers::providers::Http>,
            >,
        >,
    ),
    #[error("EthersProviderError: {0}")]
    EthersProviderError(#[from] ethers::providers::ProviderError),
    #[error("EthersNonceManagerError: {0}")]
    EthersNonceManagerError(
        #[from]
        ethers::middleware::nonce_manager::NonceManagerError<
            ethers::providers::Provider<ethers::providers::Http>,
        >,
    ),
    #[error("HexError: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Hyperliquid error: {0}")]
    HyperliquidError(#[from] hyperliquid_rust_sdk::Error),
    #[error("rustc hex error: {0}")]
    RustcHexError(#[from] rustc_hex::FromHexError),
    #[error("sec1 error: {0}")]
    Sec1Error(#[from] sec1::Error),
    #[error("wasm-bindgen JsError: {0}")]
    JsError(String),
    #[error("Failed to create payload: {0}")]
    FailedToCreatePayload(String),
    #[error("Failed to convert payload to [u8; 32]: {:?}", .0)]
    FailedToConvertPayloadTo32Bytes(Vec<u8>),
    #[error("Failed to convert payload to [u8; 20]: {:?}", .0)]
    FailedToConvertPayloadTo20Bytes(Vec<u8>),
    #[error("MPC Signature not found")]
    MPCSignatureNotFound,
    #[error("Other: {0}")]
    Other(String),
    #[error("serde_wasm_bindgen error: {0}")]
    SerdeWasmBindgenError(#[from] serde_wasm_bindgen::Error),
    #[error("rlp error: {0}")]
    RlpError(#[from] rlp::DecoderError),
}

impl From<Error> for JsValue {
    fn from(value: Error) -> Self {
        JsValue::from_str(&value.to_string())
    }
}
