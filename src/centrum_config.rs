//! Centrum specific configuration

#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
pub extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::{H256, U256};
// use sp_runtime::MultiSignature;
use subxt::{
    config::{DefaultExtrinsicParams, DefaultExtrinsicParamsBuilder, Hasher, Header},
    Config,
};

use sp_crypto_hashing;

pub use centrum_runtime::{
    AccountId as CentrumAccountId, Address as CentrumAddress, BlockNumber as CentrumBlockNumber,
    Hash as CentrumHash, Signature as CentrumSignature,
};

// use centrum_primitives::MultiSignatureOrPasskeySignature;

/// Default set of commonly used types by Substrate runtimes.
// Note: We only use this at the type level, so it should be impossible to
// create an instance of it.
// The trait implementations exist just to make life easier,
// but shouldn't strictly be necessary since users can't instantiate this type.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum CentrumConfig {}

impl Config for CentrumConfig {
    type Hash = CentrumHash;
    type AccountId = CentrumAccountId;
    type Address = CentrumAddress;
    type Signature = CentrumSignature;
    type Hasher = BlakeTwo256;
    type Header = SubstrateHeader<CentrumBlockNumber, BlakeTwo256>;
    type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
    type AssetId = u32;
}

/// Wrapper for a `CentrumAccountId`.
#[derive(
    Clone,
    Encode,
    Decode,
    TypeInfo,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    MaxEncodedLen,
    Serialize,
    Deserialize,
)]
pub struct CentrumMultiAccount(pub CentrumAccountId);

impl From<CentrumMultiAccount> for CentrumAddress {
    fn from(value: CentrumMultiAccount) -> Self {
        value.0.into()
    }
}

impl From<CentrumMultiAccount> for CentrumAccountId {
    fn from(value: CentrumMultiAccount) -> Self {
        value.0
    }
}

impl From<CentrumAccountId> for CentrumMultiAccount {
    fn from(value: CentrumAccountId) -> Self {
        CentrumMultiAccount(value)
    }
}

impl From<[u8; 32]> for CentrumMultiAccount {
    fn from(value: [u8; 32]) -> Self {
        CentrumMultiAccount(sp_core::crypto::AccountId32::new(value).into())
    }
}

impl From<sp_core::crypto::AccountId32> for CentrumMultiAccount {
    fn from(value: sp_core::crypto::AccountId32) -> Self {
        CentrumMultiAccount(value.into())
    }
}

/// Wrapper for `CentrumSignature`
#[derive(
    Eq, PartialEq, Clone, Encode, Decode, Debug, TypeInfo, Serialize, Deserialize, MaxEncodedLen,
)]
pub struct CentrumMultiSignature(pub CentrumSignature);

impl From<CentrumMultiSignature> for CentrumSignature {
    fn from(value: CentrumMultiSignature) -> Self {
        value.0
    }
}

impl From<CentrumSignature> for CentrumMultiSignature {
    fn from(value: CentrumSignature) -> Self {
        CentrumMultiSignature(value)
    }
}

impl From<subxt_signer::sr25519::Keypair> for CentrumMultiSigner {
    fn from(pair: subxt_signer::sr25519::Keypair) -> Self {
        CentrumMultiSigner(pair)
    }
}

/// An idea to abstract over the different signers
#[derive(Debug, Clone)]
pub struct CentrumMultiSigner(pub subxt_signer::sr25519::Keypair);

impl subxt::tx::Signer<CentrumConfig> for CentrumMultiSigner {
    fn account_id(&self) -> <CentrumConfig as Config>::AccountId {
        CentrumAccountId::PublicKey(self.0.public_key().0.into())
    }

    fn address(&self) -> <CentrumConfig as Config>::Address {
        CentrumAccountId::PublicKey(self.0.public_key().0.into()).into()
    }

    fn sign(&self, signer_payload: &[u8]) -> <CentrumConfig as Config>::Signature {
        let signature = self.0.sign(signer_payload);
        CentrumSignature::new(sp_runtime::MultiSignature::Sr25519(signature.0.into()))
    }
}

/// A struct representing the signed extra and additional parameters required
/// to construct a transaction for the default substrate node.
pub type SubstrateExtrinsicParams<T> = DefaultExtrinsicParams<T>;

/// A builder which leads to [`SubstrateExtrinsicParams`] being constructed.
/// This is what you provide to methods like `sign_and_submit()`.
pub type SubstrateExtrinsicParamsBuilder<T> = DefaultExtrinsicParamsBuilder<T>;

/// A type that can hash values using the blaks2_256 algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode)]
pub struct BlakeTwo256;

impl Hasher for BlakeTwo256 {
    type Output = H256;
    fn hash(s: &[u8]) -> Self::Output {
        sp_crypto_hashing::blake2_256(s).into()
    }
}

/// A generic Substrate header type, adapted from `sp_runtime::generic::Header`.
/// The block number and hasher can be configured to adapt this for other nodes.
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubstrateHeader<N: Copy + Into<U256> + TryFrom<U256>, H: Hasher> {
    /// The parent hash.
    pub parent_hash: H::Output,
    /// The block number.
    #[serde(
        serialize_with = "serialize_number",
        deserialize_with = "deserialize_number"
    )]
    #[codec(compact)]
    pub number: N,
    /// The state trie merkle root
    pub state_root: H::Output,
    /// The merkle root of the extrinsics.
    pub extrinsics_root: H::Output,
    /// A chain-specific digest of data useful for light clients or referencing auxiliary data.
    pub digest: Digest,
}

impl<N, H> Header for SubstrateHeader<N, H>
where
    N: Copy + Into<u64> + Into<U256> + TryFrom<U256> + Encode,
    H: Hasher + Encode,
    SubstrateHeader<N, H>: Encode + Decode,
{
    type Number = N;
    type Hasher = H;
    fn number(&self) -> Self::Number {
        self.number
    }
}

/// Generic header digest. From `sp_runtime::generic::digest`.
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Default)]
pub struct Digest {
    /// A list of digest items.
    pub logs: Vec<DigestItem>,
}

/// Digest item that is able to encode/decode 'system' digest items and
/// provide opaque access to other items. From `sp_runtime::generic::digest`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DigestItem {
    /// A pre-runtime digest.
    ///
    /// These are messages from the consensus engine to the runtime, although
    /// the consensus engine can (and should) read them itself to avoid
    /// code and state duplication. It is erroneous for a runtime to produce
    /// these, but this is not (yet) checked.
    ///
    /// NOTE: the runtime is not allowed to panic or fail in an `on_initialize`
    /// call if an expected `PreRuntime` digest is not present. It is the
    /// responsibility of a external block verifier to check this. Runtime API calls
    /// will initialize the block without pre-runtime digests, so initialization
    /// cannot fail when they are missing.
    PreRuntime(ConsensusEngineId, Vec<u8>),

    /// A message from the runtime to the consensus engine. This should *never*
    /// be generated by the native code of any consensus engine, but this is not
    /// checked (yet).
    Consensus(ConsensusEngineId, Vec<u8>),

    /// Put a Seal on it. This is only used by native code, and is never seen
    /// by runtimes.
    Seal(ConsensusEngineId, Vec<u8>),

    /// Some other thing. Unsupported and experimental.
    Other(Vec<u8>),

    /// An indication for the light clients that the runtime execution
    /// environment is updated.
    ///
    /// Currently this is triggered when:
    /// 1. Runtime code blob is changed or
    /// 2. `heap_pages` value is changed.
    RuntimeEnvironmentUpdated,
}

// From sp_runtime::generic, DigestItem enum indexes are encoded using this:
#[repr(u32)]
#[derive(Encode, Decode)]
enum DigestItemType {
    Other = 0u32,
    Consensus = 4u32,
    Seal = 5u32,
    PreRuntime = 6u32,
    RuntimeEnvironmentUpdated = 8u32,
}
impl Encode for DigestItem {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();

        match self {
            Self::Consensus(val, data) => {
                DigestItemType::Consensus.encode_to(&mut v);
                (val, data).encode_to(&mut v);
            }
            Self::Seal(val, sig) => {
                DigestItemType::Seal.encode_to(&mut v);
                (val, sig).encode_to(&mut v);
            }
            Self::PreRuntime(val, data) => {
                DigestItemType::PreRuntime.encode_to(&mut v);
                (val, data).encode_to(&mut v);
            }
            Self::Other(val) => {
                DigestItemType::Other.encode_to(&mut v);
                val.encode_to(&mut v);
            }
            Self::RuntimeEnvironmentUpdated => {
                DigestItemType::RuntimeEnvironmentUpdated.encode_to(&mut v);
            }
        }

        v
    }
}
impl Decode for DigestItem {
    fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
        let item_type: DigestItemType = Decode::decode(input)?;
        match item_type {
            DigestItemType::PreRuntime => {
                let vals: (ConsensusEngineId, Vec<u8>) = Decode::decode(input)?;
                Ok(Self::PreRuntime(vals.0, vals.1))
            }
            DigestItemType::Consensus => {
                let vals: (ConsensusEngineId, Vec<u8>) = Decode::decode(input)?;
                Ok(Self::Consensus(vals.0, vals.1))
            }
            DigestItemType::Seal => {
                let vals: (ConsensusEngineId, Vec<u8>) = Decode::decode(input)?;
                Ok(Self::Seal(vals.0, vals.1))
            }
            DigestItemType::Other => Ok(Self::Other(Decode::decode(input)?)),
            DigestItemType::RuntimeEnvironmentUpdated => Ok(Self::RuntimeEnvironmentUpdated),
        }
    }
}

/// Consensus engine unique ID. From `sp_runtime::ConsensusEngineId`.
pub type ConsensusEngineId = [u8; 4];

impl serde::Serialize for DigestItem {
    fn serialize<S>(&self, seq: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.using_encoded(|bytes| impl_serde::serialize::serialize(bytes, seq))
    }
}

impl<'a> serde::Deserialize<'a> for DigestItem {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let r = impl_serde::serialize::deserialize(de)?;
        Decode::decode(&mut &r[..])
            .map_err(|e| serde::de::Error::custom(format!("Decode error: {e}")))
    }
}

fn serialize_number<S, T: Copy + Into<U256>>(val: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let u256: U256 = (*val).into();
    serde::Serialize::serialize(&u256, s)
}

fn deserialize_number<'a, D, T: TryFrom<U256>>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'a>,
{
    // At the time of writing, Smoldot gives back block numbers in numeric rather
    // than hex format. So let's support deserializing from both here:
    let number_or_hex = NumberOrHex::deserialize(d)?;
    let u256 = number_or_hex.into_u256();
    TryFrom::try_from(u256).map_err(|_| serde::de::Error::custom("Try from failed"))
}

/// A number type that can be serialized both as a number or a string that encodes a number in a
/// string.
///
/// We allow two representations of the block number as input. Either we deserialize to the type
/// that is specified in the block type or we attempt to parse given hex value.
///
/// The primary motivation for having this type is to avoid overflows when using big integers in
/// JavaScript (which we consider as an important RPC API consumer).
#[derive(Copy, Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum NumberOrHex {
    /// The number represented directly.
    Number(u64),
    /// Hex representation of the number.
    Hex(U256),
}

impl NumberOrHex {
    /// Converts this number into an U256.
    pub fn into_u256(self) -> U256 {
        match self {
            NumberOrHex::Number(n) => n.into(),
            NumberOrHex::Hex(h) => h,
        }
    }
}

impl From<NumberOrHex> for U256 {
    fn from(num_or_hex: NumberOrHex) -> U256 {
        num_or_hex.into_u256()
    }
}

macro_rules! into_number_or_hex {
    ($($t: ty)+) => {
        $(
            impl From<$t> for NumberOrHex {
                fn from(x: $t) -> Self {
                    NumberOrHex::Number(x.into())
                }
            }
        )+
    }
}
into_number_or_hex!(u8 u16 u32 u64);

impl From<u128> for NumberOrHex {
    fn from(n: u128) -> Self {
        NumberOrHex::Hex(n.into())
    }
}

impl From<U256> for NumberOrHex {
    fn from(n: U256) -> Self {
        NumberOrHex::Hex(n)
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;

//     // Smoldot returns numeric block numbers in the header at the time of writing;
//     // ensure we can deserialize them properly.
//     #[test]
//     fn can_deserialize_numeric_block_number() {
//         let numeric_block_number_json = r#"
//             {
//                 "digest": {
//                     "logs": []
//                 },
//                 "extrinsicsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
//                 "number": 4,
//                 "parentHash": "0xcb2690b2c85ceab55be03fc7f7f5f3857e7efeb7a020600ebd4331e10be2f7a5",
//                 "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000"
//             }
//         "#;

//         let header: SubstrateHeader<u32, BlakeTwo256> =
//             serde_json::from_str(numeric_block_number_json).expect("valid block header");
//         assert_eq!(header.number(), 4);
//     }

//     // Substrate returns hex block numbers; ensure we can also deserialize those OK.
//     #[test]
//     fn can_deserialize_hex_block_number() {
//         let numeric_block_number_json = r#"
//             {
//                 "digest": {
//                     "logs": []
//                 },
//                 "extrinsicsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
//                 "number": "0x04",
//                 "parentHash": "0xcb2690b2c85ceab55be03fc7f7f5f3857e7efeb7a020600ebd4331e10be2f7a5",
//                 "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000"
//             }
//         "#;

//         let header: SubstrateHeader<u32, BlakeTwo256> =
//             serde_json::from_str(numeric_block_number_json).expect("valid block header");
//         assert_eq!(header.number(), 4);
//     }
// }
