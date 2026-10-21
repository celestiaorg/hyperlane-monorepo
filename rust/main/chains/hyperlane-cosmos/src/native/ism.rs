use std::str::FromStr;

use cosmrs::Any;
use hex::ToHex;
use hyperlane_cosmos_rs::{
    hyperlane::core::interchain_security::v1::{
        MerkleRootMultisigIsm, MessageIdMultisigIsm, NoopIsm, RoutingIsm as CosmosRoutingIsm,
    },
    prost::{Message, Name},
};
use tonic::async_trait;

use hyperlane_core::{
    AggregationIsm, ChainCommunicationError, ChainResult, ContractLocator, HyperlaneChain,
    HyperlaneContract, HyperlaneDomain, HyperlaneMessage, HyperlaneProvider,
    InterchainSecurityModule, Metadata, ModuleType, MultisigIsm, RawHyperlaneMessage, RoutingIsm,
    H160, H256, U256,
};

use crate::{CosmosProvider, HyperlaneCosmosError};

use super::module_query_client::ModuleQueryClient;

/// The `AggregationISM` of the hyperlane-cosmos module
/// (`hyperlane.core.interchain_security.v1.AggregationISM`).
///
/// It is not part of `hyperlane-cosmos-rs` yet, so the message is declared here.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CosmosAggregationIsm {
    /// id of the ISM
    #[prost(string, tag = "1")]
    pub id: String,
    /// owner of the ISM
    #[prost(string, tag = "2")]
    pub owner: String,
    /// ids of the sub-ISMs; their order defines the index in the aggregation metadata
    #[prost(string, repeated, tag = "3")]
    pub modules: Vec<String>,
    /// number of sub-ISMs that must verify a message
    #[prost(uint32, tag = "4")]
    pub threshold: u32,
}

impl Name for CosmosAggregationIsm {
    const NAME: &'static str = "AggregationISM";
    const PACKAGE: &'static str = "hyperlane.core.interchain_security.v1";
}

/// Cosmos Native ISM
#[derive(Debug)]
pub struct CosmosNativeIsm {
    /// The domain of the ISM contract.
    domain: HyperlaneDomain,
    /// The address of the ISM contract.
    address: H256,
    /// The provider for the ISM contract.
    provider: CosmosProvider<ModuleQueryClient>,
}

/// The Cosmos Interchain Security Module Implementation.
impl CosmosNativeIsm {
    /// Creates a new Cosmos Interchain Security Module.
    pub fn new(
        provider: CosmosProvider<ModuleQueryClient>,
        locator: ContractLocator,
    ) -> ChainResult<Self> {
        Ok(Self {
            domain: locator.domain.clone(),
            address: locator.address,
            provider,
        })
    }

    async fn get_ism(&self) -> ChainResult<Any> {
        let ism = self.provider.query().ism(self.address.encode_hex()).await?;
        ism.ism.ok_or_else(|| {
            ChainCommunicationError::from_other_str(&format!(
                "Empty ism response for: {:?}",
                self.address
            ))
        })
    }
}

impl HyperlaneContract for CosmosNativeIsm {
    /// Return the address of this contract
    fn address(&self) -> H256 {
        self.address
    }
}

impl HyperlaneChain for CosmosNativeIsm {
    /// Return the Domain
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    /// A provider for the chain
    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(self.provider.clone())
    }
}

/// Interface for the InterchainSecurityModule chain contract. Allows abstraction over
/// different chains
#[async_trait]
impl InterchainSecurityModule for CosmosNativeIsm {
    /// Returns the module type of the ISM compliant with the corresponding
    /// metadata offchain fetching and onchain formatting standard.
    async fn module_type(&self) -> ChainResult<ModuleType> {
        let ism = self.get_ism().await?;
        match ism.type_url.as_str() {
            t if t == MessageIdMultisigIsm::type_url() => Ok(ModuleType::MessageIdMultisig),
            t if t == MerkleRootMultisigIsm::type_url() => Ok(ModuleType::MerkleRootMultisig),
            t if t == CosmosRoutingIsm::type_url() => Ok(ModuleType::Routing),
            t if t == CosmosAggregationIsm::type_url() => Ok(ModuleType::Aggregation),
            t if t == NoopIsm::type_url() => Ok(ModuleType::Null),
            other => Err(ChainCommunicationError::from_other_str(&format!(
                "Unknown ISM type: {other}"
            ))),
        }
    }

    /// Dry runs the `verify()` ISM call and returns `Some(gas_estimate)` if the call
    /// succeeds.
    ///
    /// The aggregation metadata builder uses this to only count sub-ISMs whose metadata
    /// verifies. The module's `VerifyDryRun` query does not return a gas estimate, so a
    /// constant is returned for every verified call.
    async fn dry_run_verify(
        &self,
        message: &HyperlaneMessage,
        metadata: &Metadata,
    ) -> ChainResult<Option<U256>> {
        let response = self
            .provider
            .query()
            .verify_dry_run(
                self.address.encode_hex(),
                RawHyperlaneMessage::from(message),
                metadata.to_vec(),
            )
            .await;

        match response {
            Ok(response) if response.verified => Ok(Some(1.into())),
            // A failed verification is returned as an error by the module.
            _ => Ok(None),
        }
    }
}

/// Interface for the MultisigIsm chain contract. Allows abstraction over
/// different chains
#[async_trait]
impl MultisigIsm for CosmosNativeIsm {
    /// Returns the validator and threshold needed to verify message
    async fn validators_and_threshold(
        &self,
        _message: &HyperlaneMessage,
    ) -> ChainResult<(Vec<H256>, u8)> {
        let ism = self.get_ism().await?;
        match ism.type_url.as_str() {
            t if t == MerkleRootMultisigIsm::type_url() => {
                let ism = MerkleRootMultisigIsm::decode(ism.value.as_slice())
                    .map_err(HyperlaneCosmosError::from)?;
                let validators = ism
                    .validators
                    .iter()
                    .map(|v| H160::from_str(v).map(H256::from))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((validators, ism.threshold as u8))
            }
            t if t == MessageIdMultisigIsm::type_url() => {
                let ism = MessageIdMultisigIsm::decode(ism.value.as_slice())
                    .map_err(HyperlaneCosmosError::from)?;
                let validators = ism
                    .validators
                    .iter()
                    .map(|v| H160::from_str(v).map(H256::from))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((validators, ism.threshold as u8))
            }
            _ => Err(ChainCommunicationError::from_other_str(&format!(
                "ISM {:?} not a multi sig ism",
                self.address
            ))),
        }
    }
}

/// Interface for the RoutingIsm chain contract. Allows abstraction over
/// different chains
#[async_trait]
impl RoutingIsm for CosmosNativeIsm {
    /// Returns the ISM needed to verify message
    async fn route(&self, message: &HyperlaneMessage) -> ChainResult<H256> {
        let ism = self.get_ism().await?;
        match ism.type_url.as_str() {
            t if t == CosmosRoutingIsm::type_url() => {
                let ism = CosmosRoutingIsm::decode(ism.value.as_slice())
                    .map_err(HyperlaneCosmosError::from)?;
                let route = ism
                    .routes
                    .iter()
                    .find(|r| r.domain == message.origin)
                    .ok_or_else(|| {
                        ChainCommunicationError::from_other_str(&format!(
                            "Route not found for message with origin domain: {}",
                            message.origin
                        ))
                    })?;
                Ok(H256::from_str(&route.ism)?)
            }
            _ => Err(ChainCommunicationError::from_other_str(&format!(
                "ISM {:?} not a routing ism",
                self.address
            ))),
        }
    }
}

/// Interface for the AggregationIsm chain contract. Allows abstraction over
/// different chains
#[async_trait]
impl AggregationIsm for CosmosNativeIsm {
    /// Returns the `m` ISMs and `n` threshold needed to n-of-m verify the message
    async fn modules_and_threshold(
        &self,
        _message: &HyperlaneMessage,
    ) -> ChainResult<(Vec<H256>, u8)> {
        let ism = self.get_ism().await?;
        if ism.type_url != CosmosAggregationIsm::type_url() {
            return Err(ChainCommunicationError::from_other_str(&format!(
                "ISM {:?} not an aggregation ism",
                self.address
            )));
        }
        decode_modules_and_threshold(ism.value.as_slice())
    }
}

fn decode_modules_and_threshold(value: &[u8]) -> ChainResult<(Vec<H256>, u8)> {
    let ism = CosmosAggregationIsm::decode(value).map_err(HyperlaneCosmosError::from)?;
    let modules = ism
        .modules
        .iter()
        .map(|module| H256::from_str(module))
        .collect::<Result<Vec<_>, _>>()?;
    let threshold = u8::try_from(ism.threshold).map_err(|_| {
        ChainCommunicationError::from_other_str(&format!(
            "aggregation ism threshold {} exceeds u8",
            ism.threshold
        ))
    })?;
    Ok((modules, threshold))
}

#[cfg(test)]
mod tests {
    use super::*;

    // AggregationISM encoded by hyperlane-cosmos (Go, gogoproto) with 3 modules and threshold 2.
    const GO_ENCODED_AGGREGATION_ISM: &str = "0a42307837323666373537343635373235663639373336643030303030303030303030303030303030303030303030303030303230303030303030303030303030303034122f63656c657374696131776c393973756d617768707471617177657a396a34656b676130387064616a63706c773534701a423078373236663735373436353732356636393733366430303030303030303030303030303030303030303030303030303035303030303030303030303030303030311a423078373236663735373436353732356636393733366430303030303030303030303030303030303030303030303030303035303030303030303030303030303030321a423078373236663735373436353732356636393733366430303030303030303030303030303030303030303030303030303035303030303030303030303030303030332002";

    #[test]
    fn aggregation_ism_type_url_matches_hyperlane_cosmos() {
        assert_eq!(
            CosmosAggregationIsm::type_url(),
            "/hyperlane.core.interchain_security.v1.AggregationISM"
        );
    }

    #[test]
    fn decodes_modules_and_threshold_encoded_by_hyperlane_cosmos() {
        let value = hex::decode(GO_ENCODED_AGGREGATION_ISM).unwrap();

        let (modules, threshold) = decode_modules_and_threshold(&value).unwrap();

        assert_eq!(
            modules,
            vec![
                H256::from_str(
                    "0x726f757465725f69736d00000000000000000000000000050000000000000001"
                )
                .unwrap(),
                H256::from_str(
                    "0x726f757465725f69736d00000000000000000000000000050000000000000002"
                )
                .unwrap(),
                H256::from_str(
                    "0x726f757465725f69736d00000000000000000000000000050000000000000003"
                )
                .unwrap(),
            ]
        );
        assert_eq!(threshold, 2);
    }

    #[test]
    fn rejects_threshold_exceeding_u8() {
        let value = CosmosAggregationIsm {
            threshold: 256,
            ..Default::default()
        }
        .encode_to_vec();

        assert!(decode_modules_and_threshold(&value).is_err());
    }
}
