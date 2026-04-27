use crate::{AirgapError, cfg::network::Network};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provider {
    pub network: Network,
    pub kind: ProviderKind,
    pub rpc_url: Cow<'static, str>,
    pub wallet_url: Cow<'static, str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Lava,
    Fastnear,
}

impl std::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lava => write!(f, "lava"),
            Self::Fastnear => write!(f, "fastnear"),
        }
    }
}

impl FromStr for ProviderKind {
    type Err = AirgapError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "lava" => Ok(Self::Lava),
            "fastnear" => Ok(Self::Fastnear),
            _ => Err(AirgapError::InvalidRpcProvider(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonRpc {
    MainnetLava(Provider),
    MainnetFastnear(Provider),
    TestnetLava(Provider),
    TestnetFastnear(Provider),
}

impl JsonRpc {
    pub fn new(network: Network, provider: ProviderKind) -> Self {
        let provider = Provider::new(network, provider);
        match (network, provider.kind) {
            (Network::Mainnet, ProviderKind::Lava) => Self::MainnetLava(provider),
            (Network::Mainnet, ProviderKind::Fastnear) => Self::MainnetFastnear(provider),
            (Network::Testnet, ProviderKind::Lava) => Self::TestnetLava(provider),
            (Network::Testnet, ProviderKind::Fastnear) => Self::TestnetFastnear(provider),
        }
    }

    pub fn provider_config(&self) -> &Provider {
        match self {
            Self::MainnetLava(provider)
            | Self::MainnetFastnear(provider)
            | Self::TestnetLava(provider)
            | Self::TestnetFastnear(provider) => provider,
        }
    }

    pub fn network(&self) -> Network {
        self.provider_config().network
    }

    pub fn rpc_url(&self) -> &str {
        self.provider_config().rpc_url.as_ref()
    }

    pub fn wallet_url(&self) -> &str {
        self.provider_config().wallet_url.as_ref()
    }

    pub fn provider(&self) -> &Provider {
        self.provider_config()
    }

    pub fn config_key(&self) -> &'static str {
        match self {
            Self::MainnetFastnear(_) => "mainnet-fastnear",
            Self::MainnetLava(_) => "mainnet-lava",
            Self::TestnetFastnear(_) => "testnet-fastnear",
            Self::TestnetLava(_) => "testnet-lava",
        }
    }
}

impl Provider {
    pub fn new(network: Network, kind: ProviderKind) -> Self {
        let rpc_url = match (network, kind) {
            (Network::Mainnet, ProviderKind::Fastnear) => "https://rpc.mainnet.fastnear.com/",
            (Network::Mainnet, ProviderKind::Lava) => "https://near.lava.build/",
            (Network::Testnet, ProviderKind::Fastnear) => "https://test.rpc.fastnear.com/",
            (Network::Testnet, ProviderKind::Lava) => "https://neart.lava.build/",
        };

        let wallet_url = match network {
            Network::Mainnet => "https://app.mynearwallet.com/",
            Network::Testnet => "https://testnet.mynearwallet.com/",
        };

        Self {
            network,
            kind,
            rpc_url: Cow::Borrowed(rpc_url),
            wallet_url: Cow::Borrowed(wallet_url),
        }
    }
}

impl std::fmt::Display for JsonRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.config_key())
    }
}

impl FromStr for JsonRpc {
    type Err = AirgapError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mainnet-fastnear" => Ok(Self::new(Network::Mainnet, ProviderKind::Fastnear)),
            "mainnet-lava" => Ok(Self::new(Network::Mainnet, ProviderKind::Lava)),
            "testnet-fastnear" => Ok(Self::new(Network::Testnet, ProviderKind::Fastnear)),
            "testnet-lava" => Ok(Self::new(Network::Testnet, ProviderKind::Lava)),
            _ => Err(AirgapError::InvalidRpcProvider(value.to_owned())),
        }
    }
}
