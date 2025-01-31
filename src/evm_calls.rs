use crate::*;

pub use ethers::{
    abi::Address as ContractAddress,
    middleware::{MiddlewareBuilder, NonceManagerMiddleware},
    prelude::{Http, Provider as EvmProvider},
    providers::Middleware,
    types::{
        transaction::eip2718::TypedTransaction, Bytes, NameOrAddress, TransactionReceipt,
        TransactionRequest, U256,
    },
};
pub use hyperliquid_rust_sdk::{BaseUrl, ExchangeClient, InfoClient, MarketOrderParams};
pub use rlp::Decodable;

pub async fn evm_create_transfer_payload(
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
        .await?;
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

pub async fn avalanche_liquid_stake_payload(
    evm_provider: Arc<EvmClient>,
    from: PublicKey,
    amount: Option<u128>,
) -> Result<TypedTransaction, Error> {
    let chain_id = evm_provider.get_chainid().await?.as_u64();
    let is_testnet = chain_id == 43113;
    let nonce = evm_provider.next();

    let ca = if is_testnet {
        ContractAddress::from_str(AVALANCHE_LIQUID_STAKE_TESTNET)?
    } else {
        ContractAddress::from_str(AVALANCHE_LIQUID_STAKE_MAINNET)?
    };
    let to = NameOrAddress::from(ca.clone());
    let contract = AvaxLiquidStakingANKR::new(ca, evm_provider.clone());

    let call = contract.stake_and_claim_certs();
    let calldata: Bytes = call
        .calldata()
        .ok_or(Error::Other("No calldata".to_string()))?;

    let value = amount.unwrap_or(1_000_000_000_000_000_000u128);

    let mut eth_transaction: TypedTransaction = TransactionRequest {
        from: Some(from.clone().to_eth_address()),
        to: Some(to.clone()),
        value: Some(value.into()),
        nonce: Some(nonce),
        chain_id: Some(chain_id.into()),
        gas: None,
        gas_price: None,
        data: Some(calldata),
    }
    .into();

    evm_provider
        .fill_transaction(&mut eth_transaction, None)
        .await?;

    Ok(eth_transaction)
}

pub async fn avalanche_liquid_unstake_payload(
    evm_provider: Arc<EvmClient>,
    from: PublicKey,
) -> Result<TypedTransaction, Error> {
    let chain_id = evm_provider.get_chainid().await?.as_u64();
    let is_testnet = chain_id == 43113;
    let nonce = evm_provider.next();

    let ca = if is_testnet {
        ContractAddress::from_str(AVALANCHE_LIQUID_STAKE_TESTNET)?
    } else {
        ContractAddress::from_str(AVALANCHE_LIQUID_STAKE_MAINNET)?
    };
    let to = NameOrAddress::from(ca.clone());
    let contract = AvaxLiquidStakingANKR::new(ca, evm_provider.clone());

    let call = contract.claim_certs(0u128.into());
    let calldata: Bytes = call
        .calldata()
        .ok_or(Error::Other("No calldata".to_string()))?;

    let mut eth_transaction: TypedTransaction = TransactionRequest {
        from: Some(from.clone().to_eth_address()),
        to: Some(to.clone()),
        value: Some(0u128.into()),
        nonce: Some(nonce),
        chain_id: Some(chain_id.into()),
        gas: None,
        gas_price: None,
        data: Some(calldata),
    }
    .into();

    evm_provider
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
