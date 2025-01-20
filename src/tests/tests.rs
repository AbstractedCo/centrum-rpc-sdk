use crate::*;

async fn alice_faucet(
    rpc: &CentrumRpcClient,
    client: &CentrumClient,
    dest: &CentrumMultiSigner,
) -> Result<(), Box<dyn std::error::Error>> {
    let alice_signer = csigner();

    let staticacc = Static::from(dest.account_id());

    let staticmd = Static::from(sp_runtime::MultiAddress::Id(staticacc));

    let payload = runtime::tx()
        .balances()
        .transfer_keep_alive(staticmd, 1_000_000_000_000u128.into());

    let partial =
        create_partial_extrinsic(rpc, client, alice_signer.account_id(), Box::new(payload)).await?;

    let signature = demo_sign_native_with_signer(&partial, &alice_signer).await;

    let signed =
        apply_native_signature_to_transaction(&partial, alice_signer.account_id(), signature).await;

    submit_native_transaction(signed).await?;

    Ok(())
}

#[ignore]
#[tokio::test(flavor = "current_thread")]
async fn demo_test_mainnet_swap_weth_for_pha_works() {
    let demo = Demo::new_from_phrase(
        "ws://127.0.0.1:9944",
        "south middle eagle purchase galaxy obscure frown giggle kit this future host",
        false,
    )
    .await
    .expect("demo_test_initialize_works");

    info!("demo_test_builds");

    alice_faucet(&demo.rpc, &demo.client, &demo.signer)
        .await
        .unwrap();

    let recipt = demo
        .submit_eth_mainnet_swap_eth_for_pha(None)
        .await
        .unwrap();
    info!("demo_test_mainnet_swap_weth_for_pha_works");
    info!("Eth recipt {:?}", recipt);
}

#[ignore]
#[tokio::test(flavor = "current_thread")]
async fn demo_test_swap_weth_to_uni_works() {
    let demo = Demo::new_from_phrase(
        "ws://127.0.0.1:9944",
        "south middle eagle purchase galaxy obscure frown giggle kit this future host",
        true,
    )
    .await
    .expect("demo_test_initialize_works");

    info!("demo_test_builds");

    alice_faucet(&demo.rpc, &demo.client, &demo.signer)
        .await
        .unwrap();

    let recipt = demo
        .submit_eth_sepolia_swap_weth_for_uni(None)
        .await
        .unwrap();
    info!("demo_test_swap_weth_to_uni_works");
    info!("Eth recipt {:?}", recipt);
}

// #[ignore]
#[tokio::test(flavor = "current_thread")]
async fn demo_test_eth_transfer_works() {
    let demo = Demo::new_from_phrase(
        "ws://127.0.0.1:9944",
        "south middle eagle purchase galaxy obscure frown giggle kit this future host",
        true,
    )
    .await
    .expect("demo_test_initialize_works");

    alice_faucet(&demo.rpc, &demo.client, &demo.signer)
        .await
        .unwrap();

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
#[tokio::test(flavor = "current_thread")]
async fn demo_test_bridge_to_base_works() {
    let demo = Demo::new_from_phrase(
        "ws://127.0.0.1:9944",
        "south middle eagle purchase galaxy obscure frown giggle kit this future host",
        true,
    )
    .await
    .expect("demo_test_initialize_works");

    alice_faucet(&demo.rpc, &demo.client, &demo.signer)
        .await
        .unwrap();

    let bridge_result = demo.submit_eth_sepolia_bridge_to_base(None).await;
    info!("eth_sepolia_bridge_to_base result: {:?}", bridge_result);
    bridge_result.unwrap();
}

// #[ignore]
#[tokio::test(flavor = "current_thread")]
async fn demo_test_account_from_phrase_works() {
    let demo = Demo::new_from_phrase(
        "ws://127.0.0.1:9944",
        "south middle eagle purchase galaxy obscure frown giggle kit this future host",
        true,
    )
    .await
    .expect("demo_test_initialize_works");

    let demo_native_address = demo.get_native_address().await;
    info!("native_address: {}", demo_native_address);

    alice_faucet(&demo.rpc, &demo.client, &demo.signer)
        .await
        .unwrap();

    let native_balance = demo.query_native_balance().await;
    info!("native_balance: {:?}", native_balance);

    let demo_btc_address = demo.get_btc_address().await;
    info!("demo_btc_address: {}", demo_btc_address);
    // can't test without wasm-pack
    // let btc_balance = demo.query_btc_balance().await.unwrap();
    // info!("btc_balance: {}", btc_balance);
    let demo_eth_address = demo.get_eth_address().await;
    info!("demo_eth_address: {}", demo_eth_address);
    let eth_balance = demo.query_eth_balance().await.unwrap_or("0".to_string());
    info!("eth_balance: {}", eth_balance);
}

#[ignore]
#[tokio::test(flavor = "current_thread")]
async fn demo_test_initialize_alice_works() {
    let demo = Demo::new_alice("ws://127.0.0.1:9944", true)
        .await
        .expect("demo_test_initialize_works");

    let demo_btc_address = demo.get_btc_address().await;
    info!("demo_btc_address: {}", demo_btc_address);
    // can't test without wasm-pack
    // let btc_balance = demo.query_btc_balance().await.unwrap();
    // info!("btc_balance: {}", btc_balance);
    let demo_eth_address = demo.get_eth_address().await;
    info!("demo_eth_address: {}", demo_eth_address);
    let eth_balance = demo.query_eth_balance().await.unwrap();
    info!("eth_balance: {}", eth_balance);
    // Err(JsError::new("demo_test_initialize_works"))
}

#[ignore]
#[tokio::test(flavor = "current_thread")]
async fn alice_submit_request_mpc_signature_works() {
    let client = start_local_client().await.unwrap();
    let rpc = start_raw_local_rpc_client().await.unwrap();

    let alice_signer = csigner();

    let partial_ext = create_partial_extrinsic(
        &rpc,
        &client,
        alice_signer.account_id(),
        request_mpc_signature_payload([0; 32]).await,
    )
    .await
    .unwrap();

    let submittable = apply_native_signature_to_transaction(
        &partial_ext,
        alice_signer.account_id(),
        demo_sign_native_with_signer(&partial_ext, &alice_signer).await,
    )
    .await;

    submit_mpc_signature_request(&client, &rpc, submittable)
        .await
        .unwrap();
}

#[ignore]
#[tokio::test(flavor = "current_thread")]
async fn alice_submit_rpc_derive_account_works() {
    let account = request_mpc_derived_account(
        &start_local_client().await.unwrap(),
        CentrumMultiAccount::from(subxt_signer::sr25519::dev::alice().public_key().0).0,
    )
    .await;

    info!("Alice Account: {:?}", account);
}

#[ignore]
#[tokio::test(flavor = "current_thread")]
async fn alice_submit_remark_works() {
    let client = start_local_client().await.unwrap();
    let rpc = start_raw_local_rpc_client().await.unwrap();

    let alice_signer = csigner();

    let partial_ext = create_partial_extrinsic(
        &rpc,
        &client,
        alice_signer.account_id(),
        create_rmrk_payload().await.unwrap(),
    )
    .await
    .unwrap();

    let submittable = apply_native_signature_to_transaction(
        &partial_ext,
        alice_signer.account_id(),
        demo_sign_native_with_signer(&partial_ext, &alice_signer).await,
    )
    .await;

    submit_native_transaction(submittable).await.unwrap();
}

// let api = start_local_client().await.unwrap();

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
//     .await.unwrap()
//     .wait_for_finalized_success()
//     .await.unwrap();

// println!("remark tx: {:?}", rmrk);

// let alice_account_sys = runtime::storage().system().account(alice_account);

// let result = api.storage().at_latest().await.unwrap().fetch(&query).await.unwrap();

// let value = result.unwrap();

// let _a = runtime::storage().system().account(&alice_account);
// let _b = runtime::storage().system().account(&bob_account);

// println!(
//     "Alice account data: {:?}",
//     api.storage().at_latest().await.unwrap().fetch(&_a).await.unwrap()
// );

// println!(
//     "Bob account data: {:?}",
//     api.storage().at_latest().await.unwrap().fetch(&_b).await.unwrap()
// );
