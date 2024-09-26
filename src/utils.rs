#![allow(dead_code)]
use codec::{Decode, Encode};
use core::marker::PhantomData;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sp_core::H256;
use subxt::{
    config::{
        substrate::{BlakeTwo256, Digest, DigestItem, SubstrateExtrinsicParams},
        Hasher, Header,
    },
    utils::{AccountId32, MultiAddress, MultiSignature},
    Config,
};

use crate::metadata::api::runtime_types::{
    avail_core::header::{extension::HeaderExtension, Header as ApiHeader},
    sp_runtime::generic::digest::{Digest as ApiDigest, DigestItem as ApiDigestItem},
};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailHeader {
    pub parent_hash: H256,
    #[serde(serialize_with = "number_to_hex", deserialize_with = "number_from_hex")]
    #[codec(compact)]
    pub number: u32,
    pub state_root: H256,
    pub extrinsics_root: H256,
    pub digest: Digest,
    pub extension: HeaderExtension,
}

impl AvailHeader {
    pub fn data_root(&self) -> H256 {
        match &self.extension {
            HeaderExtension::V3(ext) => ext.commitment.data_root,
        }
    }
}

impl Header for AvailHeader {
    type Hasher = BlakeTwo256;
    type Number = u32;

    fn number(&self) -> Self::Number {
        self.number
    }

    fn hash(&self) -> <Self::Hasher as Hasher>::Output {
        Self::Hasher::hash_of(self)
    }
}

fn number_to_hex<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("{:X}", value);
    serializer.serialize_str(&hex_string)
}

fn number_from_hex<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;
    let without_prefix = buf.trim_start_matches("0x");
    Ok(u32::from_str_radix(without_prefix, 16).unwrap())
}

impl<B, H> From<AvailHeader> for ApiHeader<B, H>
where
    B: From<u32>,
{
    fn from(h: AvailHeader) -> Self {
        Self {
            parent_hash: h.parent_hash,
            number: h.number.into(),
            state_root: h.state_root,
            extrinsics_root: h.extrinsics_root,
            digest: h.digest.into(),
            extension: h.extension,
            __ignore: PhantomData,
        }
    }
}

impl From<Digest> for ApiDigest {
    fn from(d: Digest) -> Self {
        let logs = d
            .logs
            .into_iter()
            .map(|xt_item| xt_item.into())
            .collect::<Vec<_>>();
        Self { logs }
    }
}

impl From<DigestItem> for ApiDigestItem {
    fn from(di: DigestItem) -> Self {
        match di {
            DigestItem::PreRuntime(id, data) => ApiDigestItem::PreRuntime(id, data),
            DigestItem::Consensus(id, data) => ApiDigestItem::Consensus(id, data),
            DigestItem::Seal(id, data) => ApiDigestItem::Seal(id, data),
            DigestItem::Other(data) => ApiDigestItem::Other(data),
            DigestItem::RuntimeEnvironmentUpdated => ApiDigestItem::RuntimeEnvironmentUpdated,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AvailConfig;

impl Config for AvailConfig {
    type AccountId = AccountId32;
    type Address = MultiAddress<Self::AccountId, u32>;
    type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
    type Hash = H256;
    type Hasher = BlakeTwo256;
    type Header = AvailHeader;
    type Signature = MultiSignature;
    type AssetId = u32;
}
