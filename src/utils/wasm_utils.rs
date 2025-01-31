use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/functions.js")]
extern "C" {
    #[wasm_bindgen]
    pub async fn buildTx(to: String, from: String, amount: String) -> JsValue;

    #[wasm_bindgen]
    pub async fn signPayloadPls(source: String, payload: JsValue) -> JsValue;

    #[wasm_bindgen]
    pub async fn buildUnsignedTransaction(from: String, to: String, amount: String) -> JsValue;

    #[wasm_bindgen]
    pub fn hashFromUnsignedTx(unsignedTx: JsValue) -> String;

    #[wasm_bindgen]
    pub async fn getBitcoinBalance(address: String) -> JsValue;

    #[wasm_bindgen]
    pub async fn fillTxAndSubmit(unsignedTx: JsValue, signature: String, pubkey: String)
        -> JsValue;
}
