#![cfg_attr(not(feature = "std"), no_std)]
//! # Centrum SDK heavily WIP.
//! This SDK provides a high level interface for interacting with the centrum network.
//! It provides a way to create and sign transactions using our mpc, as well as query the state of the network.
//! Using the SDK, developers can esily sign any off-chain transactions for any evm compatible chain and also interact
//! directly with them via the SDK.

use codec::Encode;
use sp_std::{str::FromStr, sync::Arc};
use std::collections::HashMap;

#[cfg(not(test))]
use log::{info, warn}; // Use log crate when building application

#[cfg(all(test, feature = "console_log_dep"))]
use log::{info, warn}; // Use log crate when building application

#[cfg(all(test, not(feature = "console_log_dep")))]
use std::{println as info, println as warn}; // Workaround to use prinltn! for logs

use subxt_signer::SecretUri;

use wasm_bindgen::prelude::*;
// use wasm_bindgen_futures::wasm_bindgen::convert::IntoWasmAbi;

pub mod btc_calls;
pub mod centrum_calls;
pub mod error;
pub mod evm_calls;
#[allow(dead_code, unused_imports)]
mod tests;
#[allow(unused_imports)]
pub mod utils;

use btc_calls::*;
use centrum_calls::*;
use evm_calls::*;

pub use utils::{centrum_config::*, *};

use contract_utils::{
    AvaxLiquidStakingANKR, L1StandardBridge, UniswapV2Router02, AVALANCHE_LIQUID_STAKE_MAINNET,
    AVALANCHE_LIQUID_STAKE_TESTNET, ERC20, ETH_MAINNET_UNISWAP_V2_ROUTER,
    ETH_SEPOLIA_BASE_STANDARD_BRIDGE_ADDRESS, ETH_SEPOLIA_UNISWAP_V2_ROUTER, PHA_MAINNET,
    UNI_SEPOLIA, WETH_MAINNET, WETH_SEPOLIA,
};
pub use error::Error;
#[allow(unused_imports)]
use signature_utils::{
    btc_sig_from_mpc_sig, eth_sign_transaction, testnet_btc_address, EthRecipt, PublicKey,
    ToEncodedPoint, HUNDRED_SATS,
};

pub type NativeClient = OnlineClient<CentrumConfig>;
pub type NativeRpcClient = LegacyRpcMethods<CentrumConfig>;
pub type EvmClient = NonceManagerMiddleware<EvmProvider<Http>>;

#[derive(Debug, Clone)]
pub struct HyperLiquidClient {
    pub info_client: Arc<InfoClient>,
    pub exchange_client: Arc<ExchangeClient>,
}

/// Struct representing a Centrum SDK client, provides a high level interface for interacting with the centrum network,
/// as well as btc and any other evm compatible chains.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct DemoClient {
    #[wasm_bindgen(skip)]
    pub native_client: NativeClient,
    #[wasm_bindgen(skip)]
    pub native_rpc: NativeRpcClient,
    #[wasm_bindgen(skip)]
    pub eth_client: Arc<EvmClient>,
    #[wasm_bindgen(skip)]
    pub avax_c_client: Arc<EvmClient>,
    #[wasm_bindgen(skip)]
    pub hyperliquid_client: HyperLiquidClient,
    #[wasm_bindgen(skip)]
    pub custom_clients_map: HashMap<String, Arc<EvmClient>>,
    #[wasm_bindgen(skip)]
    pub signer: CentrumMultiSigner,
    #[wasm_bindgen(skip)]
    pub signer_mpc_public_key: PublicKey,
    #[wasm_bindgen(skip)]
    pub compressed_public_key: CompressedPublicKey,
}

#[wasm_bindgen]
impl DemoClient {
    async fn create_clients(
        signer: CentrumMultiSigner,
        centrum_node_url: &str,
        eth_testnet: bool,
    ) -> Result<
        (
            NativeRpcClient,
            NativeClient,
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

        let avax_c_client = if eth_testnet {
            EvmProvider::<Http>::try_from("https://avalanche-fuji-c-chain-rpc.publicnode.com")
                .map_err(|_| Error::Other("failed to create rpc client".to_string()))?
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address())
        } else {
            EvmProvider::<Http>::try_from("https://avalanche-c-chain-rpc.publicnode.com")
                .map_err(|_| Error::Other("failed to create rpc client".to_string()))?
                .nonce_manager(signer_mpc_public_key.clone().to_eth_address())
        };
        avax_c_client.initialize_nonce(None).await?;

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
            avax_c_client,
            hyperliquid_client,
            signer_mpc_public_key,
            compressed_public_key,
        ))
    }

    #[wasm_bindgen(constructor)]
    pub async fn new_alice(centrum_node_url: &str, eth_testnet: bool) -> Result<DemoClient, Error> {
        #[cfg(all(debug_assertions, feature = "console_log_dep"))]
        console_log::init_with_level(log::Level::Debug)?;

        let signer = csigner();
        let (
            native_rpc,
            native_client,
            eth_client,
            avax_c_client,
            hyperliquid_client,
            signer_mpc_public_key,
            compressed_public_key,
        ) = DemoClient::create_clients(signer.clone(), centrum_node_url, eth_testnet).await?;

        Ok(DemoClient {
            native_client,
            native_rpc,
            eth_client: Arc::new(eth_client),
            avax_c_client: Arc::new(avax_c_client),
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
    ) -> Result<DemoClient, Error> {
        #[cfg(all(debug_assertions, feature = "console_log_dep"))]
        console_log::init_with_level(log::Level::Debug)?;
        let uri = SecretUri::from_str(seed_phrase).map_err(|e| Error::Other(e.to_string()))?;
        let signer: CentrumMultiSigner = subxt_signer::sr25519::Keypair::from_uri(&uri)
            .map_err(|e| Error::Other(e.to_string()))?
            .into();

        let (
            native_rpc,
            native_client,
            eth_client,
            avax_c_client,
            hyperliquid_client,
            signer_mpc_public_key,
            compressed_public_key,
        ) = DemoClient::create_clients(signer.clone(), centrum_node_url, eth_testnet).await?;

        Ok(DemoClient {
            native_client,
            native_rpc,
            eth_client: Arc::new(eth_client),
            avax_c_client: Arc::new(avax_c_client),
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

        internal_request_mpc_signature_payload(
            payload,
            &self.native_client,
            &self.native_rpc,
            &self.signer,
        )
        .await
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

        let eth_payload = evm_create_transfer_payload(
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

    pub async fn avalance_chain_transfer(
        &self,
        dest: String,
        amount: Option<u128>,
    ) -> Result<EthRecipt, Error> {
        let evm_payload = evm_create_transfer_payload(
            self.avax_c_client.clone(),
            self.signer_mpc_public_key.clone(),
            dest.as_str(),
            amount,
        )
        .await?;

        let recipt = self
            .sign_and_submit_payload_to_evm_client(self.avax_c_client.clone(), evm_payload)
            .await?;

        Ok(recipt)
    }

    pub async fn avalanche_liquid_stake(&self, amount: Option<u128>) -> Result<EthRecipt, Error> {
        let evm_payload = avalanche_liquid_stake_payload(
            self.avax_c_client.clone(),
            self.signer_mpc_public_key.clone(),
            amount,
        )
        .await?;

        let recipt = self
            .sign_and_submit_payload_to_evm_client(self.avax_c_client.clone(), evm_payload)
            .await?;

        Ok(recipt)
    }

    pub async fn avalanche_liquid_unstake(&self) -> Result<EthRecipt, Error> {
        let evm_payload = avalanche_liquid_unstake_payload(
            self.avax_c_client.clone(),
            self.signer_mpc_public_key.clone(),
        )
        .await?;

        let recipt = self
            .sign_and_submit_payload_to_evm_client(self.avax_c_client.clone(), evm_payload)
            .await?;

        Ok(recipt)
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

        let recipt = self
            .sign_and_submit_payload_to_evm_client(evm_client.clone(), eth_payload)
            .await?;

        Ok(recipt)
    }

    async fn sign_and_submit_payload_to_evm_client(
        &self,
        evm_client: Arc<EvmClient>,
        eth_payload: TypedTransaction,
    ) -> Result<EthRecipt, Error> {
        let eth_sighash = eth_payload.sighash();

        let mpc_signature = internal_request_mpc_signature_payload(
            eth_sighash.0.clone(),
            &self.native_client,
            &self.native_rpc,
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

    pub async fn query_custom_client_erc20_balance(
        &self,
        client_name: String,
        erc20_address: String,
    ) -> Result<String, Error> {
        let evm_client = self
            .custom_clients_map
            .get(&client_name)
            .ok_or(Error::Other("Client not found".to_string()))?;

        let bal = self
            .query_evm_erc20_balance(evm_client.clone(), erc20_address)
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

    pub async fn query_eth_erc20_balance(&self, erc20_address: String) -> Result<String, Error> {
        let bal = self
            .query_evm_erc20_balance(self.eth_client.clone(), erc20_address)
            .await?;

        Ok(bal.to_string())
    }

    async fn query_evm_erc20_balance(
        &self,
        evm_client: Arc<EvmClient>,
        erc20_address: String,
    ) -> Result<String, Error> {
        let ca = ContractAddress::from_str(&erc20_address)?;
        let erc20 = ERC20::new(ca, evm_client.clone());

        let bal: U256 = erc20
            .balance_of(self.signer_mpc_public_key.clone().to_eth_address())
            .call()
            .await?;

        Ok(bal.to_string())
    }

    pub async fn query_avax_balance(&self) -> Result<String, Error> {
        let bal = self
            .avax_c_client
            .get_balance(self.signer_mpc_public_key.clone().to_eth_address(), None)
            .await?;

        Ok(bal.to_string())
    }

    pub async fn query_avalanche_erc20_balance(
        &self,
        erc20_address: String,
    ) -> Result<String, Error> {
        let bal = self
            .query_evm_erc20_balance(self.avax_c_client.clone(), erc20_address)
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
            .native_client
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
