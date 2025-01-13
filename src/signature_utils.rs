use bitcoin::{Address as BitcoinAddress, Amount, CompressedPublicKey, KnownHrp};
use elliptic_curve::{
    ops::Reduce,
    point::AffineCoordinates,
    scalar::FromUintUnchecked,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    CurveArithmetic,
};
use ethers::{
    middleware::MiddlewareBuilder,
    prelude::{Http, Provider as EthProvider},
    providers::Middleware,
    types::{
        transaction::eip2718::TypedTransaction, NameOrAddress, Signature as EthersSignature,
        TransactionReceipt, TransactionRequest, H160, H256, U256,
    },
};
use k256::{
    ecdsa::{RecoveryId, VerifyingKey},
    AffinePoint, EncodedPoint, Scalar, Secp256k1,
};
use serde::{Deserialize, Serialize};
use sp_core::{
    blake2_256,
    ecdsa::{Public as ECDSAPublic, Signature as ECDSASignature},
    keccak_256,
};
use sp_runtime::traits::Verify as _;

use codec::{Decode, Encode};

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::wasm_bindgen::convert::IntoWasmAbi;

use crate::MpcSignatureDelivered;

const PATH: &[u8] = b"test";
const POINT_ZERO_ZERO_ONE_ETH: u128 = 1_000_000_000_000_000;
const HUNDRED_SATS: Amount = Amount::from_sat(100);

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicKey(pub Vec<u8>);

impl PublicKey {
    pub fn from_affine(value: <Secp256k1 as CurveArithmetic>::AffinePoint) -> Self {
        PublicKey(value.to_encoded_point(true).as_bytes().to_vec())
    }

    pub fn into_affine(&self) -> <Secp256k1 as CurveArithmetic>::AffinePoint {
        <Secp256k1 as CurveArithmetic>::AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&self.0).expect("EncodedPoint from_bytes failed."),
        )
        .expect("AffinePoint from_encoded_point failed.")
    }

    pub fn to_eth_address(self) -> H160 {
        Secp256K1PublicKey::from(self).to_eth_address()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Debug, Encode, Decode)]
pub struct Secp256K1PublicKey(pub [u8; 64]);

impl From<PublicKey> for Secp256K1PublicKey {
    fn from(pk: PublicKey) -> Secp256K1PublicKey {
        Secp256K1PublicKey::try_from(&pk.into_affine().to_encoded_point(false).as_bytes()[1..65])
            .expect("Secp256K1PublicKey try_from failed.")
    }
}

impl Secp256K1PublicKey {
    pub fn to_eth_address(&self) -> H160 {
        let pk = self.0;

        let hash = keccak_256(&pk);

        H160::from_slice(&hash[12..])
    }
}

impl TryFrom<&[u8]> for Secp256K1PublicKey {
    type Error = ();

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        data.try_into().map(Self).map_err(|_| ())
    }
}

#[derive(Clone)]
pub struct FullSignature {
    /// This is the entire first point.
    pub big_r: AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: Scalar,
}

pub fn eth_sig(
    public_key: &AffinePoint,
    big_r: AffinePoint,
    s: Scalar,
    msg_hash: Scalar,
    chain_id: u64,
) -> EthersSignature {
    let public_key = public_key.to_encoded_point(false);

    let sig = FullSignature { big_r, s };

    let r = x_coordinate_secp256k1(&sig.big_r);

    let signature = k256::ecdsa::Signature::from_scalars(r, sig.s)
        .expect("cannot create signature from cait_sith signature");

    let pk0 = VerifyingKey::recover_from_prehash(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(0).expect("cannot create recovery_id=0"),
    )
    .expect("unable to use 0 as recovery_id to recover public key")
    .to_encoded_point(false);

    let recovery_id = if public_key == pk0 {
        0
    } else {
        let pk1 = VerifyingKey::recover_from_prehash(
            &msg_hash.to_bytes(),
            &signature,
            RecoveryId::try_from(1).expect("cannot create recovery_id=1"),
        )
        .expect("unable to use 1 as recovery_id to recover public key")
        .to_encoded_point(false);

        if public_key == pk1 {
            1
        } else {
            panic!("error");
        }
    };

    let ethers_r = U256::from_big_endian(r.to_bytes().as_slice());
    let ethers_s = U256::from_big_endian(s.to_bytes().as_slice());
    let ethers_v = to_eip155_v(recovery_id, chain_id);

    EthersSignature {
        r: ethers_r,
        s: ethers_s,
        v: ethers_v,
    }
}

pub fn substrate_sig(
    public_key: &AffinePoint,
    big_r: AffinePoint,
    s: Scalar,
    msg_hash: Scalar,
) -> ECDSASignature {
    let public_key = public_key.to_encoded_point(false);

    let sig = FullSignature { big_r, s };

    let r = x_coordinate_secp256k1(&sig.big_r);

    let signature = k256::ecdsa::Signature::from_scalars(r, sig.s)
        .expect("cannot create signature from cait_sith signature");

    let pk0 = VerifyingKey::recover_from_prehash(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(0).expect("cannot create recovery_id=0"),
    )
    .expect("unable to use 0 as recovery_id to recover public key")
    .to_encoded_point(false);

    let recovery_id: u8 = if public_key == pk0 {
        0
    } else {
        let pk1 = VerifyingKey::recover_from_prehash(
            &msg_hash.to_bytes(),
            &signature,
            RecoveryId::try_from(1).expect("cannot create recovery_id=1"),
        )
        .expect("unable to use 1 as recovery_id to recover public key")
        .to_encoded_point(false);

        if public_key == pk1 {
            1
        } else {
            panic!("error");
        }
    };

    let mut ecdsa_sig = ECDSASignature::default();
    ecdsa_sig.0[..64].copy_from_slice(&signature.to_bytes());
    ecdsa_sig.0[64] = recovery_id;
    ecdsa_sig
}

pub fn btc_sig(big_r: AffinePoint, s: Scalar) -> bitcoin::ecdsa::Signature {
    let sig = FullSignature { big_r, s };

    let r = x_coordinate_secp256k1(&sig.big_r);

    let signature = k256::ecdsa::Signature::from_scalars(r, sig.s)
        .expect("cannot create signature from cait_sith signature");

    let der = signature.to_der();

    let new_sig = secp256k1::ecdsa::Signature::from_der(der.as_bytes()).unwrap();

    let btc_sig = bitcoin::ecdsa::Signature::sighash_all(new_sig);

    btc_sig
}

pub fn x_coordinate_secp256k1(point: &k256::AffinePoint) -> k256::Scalar {
    <k256::Scalar as Reduce<<k256::Secp256k1 as elliptic_curve::Curve>::Uint>>::reduce_bytes(
        &point.x(),
    )
}

pub fn to_eip155_v(recovery_id: u8, chain_id: u64) -> u64 {
    (recovery_id as u64) + 35 + chain_id * 2
}

fn scalar_from_bytes(bytes: &[u8]) -> Scalar {
    Scalar::from_uint_unchecked(k256::U256::from_be_slice(bytes))
}

fn testnet_btc_address(key: CompressedPublicKey) -> String {
    let hash = key.pubkey_hash();

    let mut prefixed = [0; 21];
    prefixed[0] = 0x1b;
    prefixed[1..].copy_from_slice(&hash[..]);
    bitcoin::base58::encode_check(&prefixed[..])
}

pub fn get_testnet_btc_address(public: PublicKey) -> String {
    let encoded_point_compressed = public.clone().into_affine().to_encoded_point(true);

    let compressed_public_key =
        CompressedPublicKey::from_slice(encoded_point_compressed.as_bytes()).unwrap();

    //let address = BitcoinAddress::p2wpkh(&compressed_public_key, KnownHrp::Mainnet);

    testnet_btc_address(compressed_public_key)
}

pub fn get_eth_address(public: PublicKey) -> String {
    format!("0x{}", hex::encode(public.clone().to_eth_address().0))
}

pub fn eth_sign_transaction(
    sig_hash: H256,
    chain_id: u64,
    mpc_signature: MpcSignatureDelivered,
    mpc_public_key: PublicKey,
) -> Result<EthersSignature, Box<dyn std::error::Error>> {
    let big_r =
        AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(mpc_signature.big_r)?).unwrap();

    let s = scalar_from_bytes(&mpc_signature.s);

    let public_key = mpc_public_key.into_affine();

    let payload_hash_scalar = scalar_from_bytes(&sig_hash.0);

    Ok(eth_sig(
        &public_key,
        big_r,
        s,
        payload_hash_scalar,
        chain_id,
    ))
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthRecipt {
    /// Transaction hash.
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Vec<u8>,
    /// Index within the block.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: u64,
    /// Hash of the block this transaction was included within.
    #[serde(rename = "blockHash")]
    pub block_hash: Option<Vec<u8>>,
    /// Number of the block this transaction was included within.
    #[serde(rename = "blockNumber")]
    pub block_number: Option<u64>,
    /// address of the sender H160 => [u8;20].
    pub from: Vec<u8>,
    // address of the receiver. null when its a contract creation transaction  H160 => [u8;20].
    pub to: Option<Vec<u8>>,
    /// Cumulative gas used within the block after this was executed.
    #[wasm_bindgen(skip)]
    #[serde(rename = "cumulativeGasUsed")]
    pub cumulative_gas_used: U256,
    /// Gas used by this transaction alone.
    ///
    /// Gas used is `None` if the the client is running in light client mode.
    #[wasm_bindgen(skip)]
    #[serde(rename = "gasUsed")]
    pub gas_used: Option<U256>,
    /// Contract address created, or `None` if not a deployment.
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<Vec<u8>>,
    /// Logs generated within this transaction.
    #[wasm_bindgen(skip)]
    pub logs: Vec<ethers::types::Log>,
    /// Status: either 1 (success) or 0 (failure). Only present after activation of [EIP-658](https://eips.ethereum.org/EIPS/eip-658)
    pub status: Option<u64>,
}

impl From<TransactionReceipt> for EthRecipt {
    fn from(value: TransactionReceipt) -> Self {
        EthRecipt {
            transaction_hash: value.transaction_hash.0.to_vec(),
            transaction_index: value.transaction_index.as_u64(),
            block_hash: value.block_hash.map(|x| x.0.to_vec()),
            block_number: value.block_number.map(|x| x.as_u64()),
            from: value.from.0.to_vec(),
            to: value.to.map(|x| x.0.to_vec()),
            cumulative_gas_used: value.cumulative_gas_used,
            gas_used: value.gas_used,
            contract_address: value.contract_address.map(|x| x.0.to_vec()),
            logs: value.logs,
            status: value.status.map(|x| x.as_u64()),
        }
    }
}

// fn add_signature_to_pdf(bytes: &[u8], signature: ECDSASignature) -> Vec<u8> {
//     let signature_string = hex::encode(signature.0);

//     let mut doc = lopdf::Document::load_from(bytes).unwrap();

//     let maybe_already_sig = doc.objects.clone().into_values().find(|o| {
//         if let lopdf::Object::String(s, lopdf::StringFormat::Literal) = o {
//             String::from_utf8(s.clone())
//                 .unwrap()
//                 .starts_with("signature")
//         } else {
//             false
//         }
//     });

//     if let Some(sig) = maybe_already_sig {
//         return bytes.to_vec();
//     }

//     doc.add_object(lopdf::Object::String(
//         format!("signature {}", signature_string).into(),
//         lopdf::StringFormat::Literal,
//     ));

//     let mut new_bytes = Vec::new();

//     doc.save_to(&mut new_bytes).unwrap();

//     new_bytes
// }
