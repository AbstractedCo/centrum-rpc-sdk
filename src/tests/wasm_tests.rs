use crate::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test_configure;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

async fn alice_faucet(
    rpc: &NativeRpcClient,
    client: &NativeClient,
    dest: &CentrumMultiSigner,
) -> Result<(), Box<dyn std::error::Error>> {
    let alice_signer = csigner();

    let staticacc = Static::from(dest.account_id());

    let staticmd = Static::from(sp_runtime::MultiAddress::Id(staticacc));

    let payload = runtime::tx()
        .balances()
        .transfer_keep_alive(staticmd, 10_000_000_000_000u128.into());

    let partial =
        create_partial_extrinsic(rpc, client, alice_signer.account_id(), Box::new(payload)).await?;

    let signature = demo_sign_native_with_signer(&partial, &alice_signer).await;

    let signed =
        apply_native_signature_to_transaction(&partial, alice_signer.account_id(), signature).await;

    submit_native_transaction(signed).await?;

    Ok(())
}

#[ignore]
#[wasm_bindgen_test]
async fn wasm_demo_test_eth_transfer_works() {
    let demo = CentrumSignerAgent::new_alice("ws://127.0.0.1:9944", true)
        .await
        .expect("demo_test_initialize_works");

    let eth_balance = demo.query_eth_balance().await.unwrap();
    info!("eth_balance: {}", eth_balance);

    let e = demo
        .submit_eth_sepolia_transfer(
            "0xc99F9d2549aa5B2BB5A07cEECe4AFf32a60ceB11".to_string(),
            None,
        )
        .await;
    info!("eth_sepolia_transfer result: {:?}", e);
}

#[ignore]
#[wasm_bindgen_test]
async fn wasm_demo_test_bridge_to_base_works() {
    wasm_bindgen_test_configure!(run_in_browser);
    let demo = CentrumSignerAgent::new_alice("ws://127.0.0.1:9944", true)
        .await
        .expect("demo_test_initialize_works");

    let bridge_result = demo.submit_eth_sepolia_bridge_to_base(None).await;
    info!("eth_sepolia_bridge_to_base result: {:?}", bridge_result);
    bridge_result.unwrap();
}

#[ignore]
#[wasm_bindgen_test]
async fn wasm_demo_test_btc_transfer_works() {
    wasm_bindgen_test_configure!(run_in_browser);
    let demo = CentrumSignerAgent::new_alice("ws://127.0.0.1:9944", true)
        .await
        .expect("demo_test_initialize_works");

    let e = demo
        .submit_btc_transfer("CFqoZmZ3ePwK5wnkhxJjJAQKJ82C7RJdmd".to_string(), None)
        .await;
    info!("btc_transfer_works result: {:?}", e);
    e.unwrap();
}

#[ignore]
#[wasm_bindgen_test]
async fn wasm_demo_test_initialize_alice_works() {
    wasm_bindgen_test_configure!(run_in_browser);
    let demo = CentrumSignerAgent::new_alice("ws://127.0.0.1:9944", true)
        .await
        .expect("demo_test_initialize_works");

    let demo_btc_address = demo.get_btc_address().await;
    info!("demo_btc_address: {}", demo_btc_address);
    let btc_balance = demo.query_btc_balance().await.unwrap();
    info!("btc_balance: {}", btc_balance);
    let demo_eth_address = demo.get_eth_address().await;
    info!("demo_eth_address: {}", demo_eth_address);
    let eth_balance = demo.query_eth_balance().await.unwrap();
    info!("eth_balance: {}", eth_balance);
    // Err(JsError::new("demo_test_initialize_works"))
}
