mod password;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use near_crypto::PublicKey;
use near_primitives::{
    hash::CryptoHash,
    transaction::{Action, Transaction, TransactionV0, TransferAction},
    types::{AccountId, Balance, Nonce},
};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use uuid::Uuid;

pub use password::{PasswordError, PasswordPolicy};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransactionRequest {
    pub id: String,
    pub network: NearNetwork,
    pub kind: TransactionKind,
    pub transaction_borsh_base64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NearNetwork {
    Mainnet,
    Testnet,
}

impl fmt::Display for NearNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
        }
    }
}

impl FromStr for NearNetwork {
    type Err = AirgapError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            _ => Err(AirgapError::InvalidNetwork(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransactionKind {
    Transfer {
        signer_id: String,
        signer_public_key: String,
        receiver_id: String,
        nonce: Nonce,
        block_hash: String,
        deposit_yocto_near: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransferRequest {
    pub request_id: String,
    pub network: NearNetwork,
    pub signer_id: String,
    pub signer_public_key: String,
    pub receiver_id: String,
    pub nonce: Nonce,
    pub block_hash: String,
    pub deposit_yocto_near: String,
}

#[derive(Debug, Clone)]
pub struct TransferDraft {
    pub network: NearNetwork,
    pub signer_id: String,
    pub signer_public_key: String,
    pub receiver_id: String,
    pub nonce: Nonce,
    pub block_hash: String,
    pub deposit_yocto_near: Balance,
}

impl TransferDraft {
    pub fn into_request(self) -> Result<UnsignedTransactionRequest, AirgapError> {
        let transaction = Transaction::V0(TransactionV0 {
            signer_id: parse_account_id("signer_id", &self.signer_id)?,
            public_key: parse_public_key(&self.signer_public_key)?,
            nonce: self.nonce,
            receiver_id: parse_account_id("receiver_id", &self.receiver_id)?,
            block_hash: parse_block_hash(&self.block_hash)?,
            actions: vec![Action::Transfer(TransferAction {
                deposit: self.deposit_yocto_near,
            })],
        });

        let transaction_borsh_base64 = STANDARD.encode(borsh::to_vec(&transaction)?);

        Ok(UnsignedTransactionRequest {
            id: Uuid::now_v7().to_string(),
            network: self.network,
            kind: TransactionKind::Transfer {
                signer_id: self.signer_id,
                signer_public_key: self.signer_public_key,
                receiver_id: self.receiver_id,
                nonce: self.nonce,
                block_hash: self.block_hash,
                deposit_yocto_near: self.deposit_yocto_near.as_yoctonear().to_string(),
            },
            transaction_borsh_base64,
        })
    }
}

pub fn request_to_pretty_json(request: &UnsignedTransactionRequest) -> Result<String, AirgapError> {
    Ok(serde_json::to_string_pretty(request)?)
}

fn parse_account_id(field: &'static str, value: &str) -> Result<AccountId, AirgapError> {
    value.parse().map_err(|source| AirgapError::InvalidAccountId {
        field,
        value: value.to_owned(),
        source: Box::new(source),
    })
}

fn parse_public_key(value: &str) -> Result<PublicKey, AirgapError> {
    value.parse().map_err(|source| AirgapError::InvalidPublicKey {
        value: value.to_owned(),
        source: Box::new(source),
    })
}

fn parse_block_hash(value: &str) -> Result<CryptoHash, AirgapError> {
    value.parse().map_err(|source| AirgapError::InvalidBlockHash {
        value: value.to_owned(),
        source,
    })
}

#[derive(Debug)]
pub enum AirgapError {
    InvalidNetwork(String),
    InvalidAccountId {
        field: &'static str,
        value: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    InvalidPublicKey {
        value: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    InvalidBlockHash {
        value: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    Borsh(std::io::Error),
    Json(serde_json::Error),
    Base64Decode(String),
    UnsupportedTransaction(String),
    RequestMismatch {
        field: &'static str,
        described: String,
        actual: String,
    },
}

impl fmt::Display for AirgapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNetwork(value) => {
                write!(f, "network must be mainnet or testnet, got {value}")
            }
            Self::InvalidAccountId { field, value, .. } => {
                write!(f, "{field} is not a valid NEAR account id: {value}")
            }
            Self::InvalidPublicKey { value, .. } => {
                write!(f, "signer_public_key is not a valid NEAR public key: {value}")
            }
            Self::InvalidBlockHash { value, .. } => {
                write!(f, "block_hash is not a valid NEAR block hash: {value}")
            }
            Self::Borsh(source) => write!(f, "failed to serialize transaction: {source}"),
            Self::Json(source) => write!(f, "failed to serialize request json: {source}"),
            Self::Base64Decode(value) => write!(f, "failed to decode base64: {value}"),
            Self::UnsupportedTransaction(message) => write!(f, "unsupported transaction: {message}"),
            Self::RequestMismatch {
                field,
                described,
                actual,
            } => write!(
                f,
                "request field {field} does not match the transaction bytes (described: {described}, actual: {actual})"
            ),
        }
    }
}

impl std::error::Error for AirgapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAccountId { source, .. } => Some(source.as_ref()),
            Self::InvalidPublicKey { source, .. } => Some(source.as_ref()),
            Self::InvalidBlockHash { source, .. } => Some(source.as_ref()),
            Self::Borsh(source) => Some(source),
            Self::Json(source) => Some(source),
            Self::InvalidNetwork(_)
            | Self::Base64Decode(_)
            | Self::UnsupportedTransaction(_)
            | Self::RequestMismatch { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransactionResponse {
    /// The original request id, for matching response to request.
    pub request_id: String,
    /// The signed transaction, borsh serialized then base64 encoded.
    #[serde(rename = "signed_transaction_as_base64", alias = "signed_transaction_borsh_base64")]
    pub signed_transaction_borsh_base64: String,
    /// The signature, separately extractable for quick verification.
    pub signature: String,
    /// The public key that produced the signature.
    pub public_key: String,
}

pub fn request_from_json(json: &str) -> Result<UnsignedTransactionRequest, AirgapError> {
    Ok(serde_json::from_str(json)?)
}

pub fn response_to_pretty_json(response: &SignedTransactionResponse) -> Result<String, AirgapError> {
    Ok(serde_json::to_string_pretty(response)?)
}

pub fn response_from_json(json: &str) -> Result<SignedTransactionResponse, AirgapError> {
    Ok(serde_json::from_str(json)?)
}

pub fn verify_transfer_request(request: &UnsignedTransactionRequest) -> Result<VerifiedTransferRequest, AirgapError> {
    let (verified, _, _) = decode_and_verify_transfer_request(request)?;
    Ok(verified)
}

pub fn sign_transfer_request(
    request: &UnsignedTransactionRequest,
    secret_key: &near_crypto::SecretKey,
) -> Result<SignedTransactionResponse, AirgapError> {
    let (_, _, transaction) = decode_and_verify_transfer_request(request)?;
    let signature = secret_key.sign(transaction.get_hash_and_size().0.as_ref());
    let signature_str = signature.to_string();
    let signed_tx = near_primitives::transaction::SignedTransaction::new(signature, transaction);
    let signed_bytes = borsh::to_vec(&signed_tx)?;

    Ok(SignedTransactionResponse {
        request_id: request.id.clone(),
        signed_transaction_borsh_base64: STANDARD.encode(&signed_bytes),
        signature: signature_str,
        public_key: secret_key.public_key().to_string(),
    })
}

impl From<std::io::Error> for AirgapError {
    fn from(source: std::io::Error) -> Self {
        Self::Borsh(source)
    }
}

impl From<serde_json::Error> for AirgapError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

fn decode_and_verify_transfer_request(
    request: &UnsignedTransactionRequest,
) -> Result<(VerifiedTransferRequest, Vec<u8>, Transaction), AirgapError> {
    let bytes = STANDARD
        .decode(&request.transaction_borsh_base64)
        .map_err(|e| AirgapError::Base64Decode(e.to_string()))?;
    let transaction: Transaction = borsh::from_slice(&bytes)?;

    let TransactionKind::Transfer {
        signer_id: described_signer_id,
        signer_public_key: described_signer_public_key,
        receiver_id: described_receiver_id,
        nonce: described_nonce,
        block_hash: described_block_hash,
        deposit_yocto_near: described_deposit,
    } = &request.kind;

    let transaction_v0 = match &transaction {
        Transaction::V0(transaction_v0) => transaction_v0,
        Transaction::V1(_) => {
            return Err(AirgapError::UnsupportedTransaction(
                "transaction version v1 is not supported".to_owned(),
            ));
        }
    };
    let [Action::Transfer(transfer)] = transaction_v0.actions.as_slice() else {
        return Err(AirgapError::UnsupportedTransaction(
            "only single-action transfer transactions are supported".to_owned(),
        ));
    };

    let verified = VerifiedTransferRequest {
        request_id: request.id.clone(),
        network: request.network,
        signer_id: transaction_v0.signer_id.to_string(),
        signer_public_key: transaction_v0.public_key.to_string(),
        receiver_id: transaction_v0.receiver_id.to_string(),
        nonce: transaction_v0.nonce,
        block_hash: transaction_v0.block_hash.to_string(),
        deposit_yocto_near: transfer.deposit.as_yoctonear().to_string(),
    };

    ensure_matches("signer_id", described_signer_id, &verified.signer_id)?;
    ensure_matches(
        "signer_public_key",
        described_signer_public_key,
        &verified.signer_public_key,
    )?;
    ensure_matches("receiver_id", described_receiver_id, &verified.receiver_id)?;
    ensure_matches("nonce", &described_nonce.to_string(), &verified.nonce.to_string())?;
    ensure_matches("block_hash", described_block_hash, &verified.block_hash)?;
    ensure_matches("deposit_yocto_near", described_deposit, &verified.deposit_yocto_near)?;

    Ok((verified, bytes, transaction))
}

fn ensure_matches(field: &'static str, described: &str, actual: &str) -> Result<(), AirgapError> {
    if described == actual {
        Ok(())
    } else {
        Err(AirgapError::RequestMismatch {
            field,
            described: described.to_owned(),
            actual: actual.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> UnsignedTransactionRequest {
        TransferDraft {
            network: NearNetwork::Testnet,
            signer_id: "alice.testnet".to_owned(),
            signer_public_key: "ed25519:11111111111111111111111111111111".to_owned(),
            receiver_id: "bob.testnet".to_owned(),
            nonce: 42,
            block_hash: "11111111111111111111111111111111".to_owned(),
            deposit_yocto_near: Balance::from_yoctonear(5),
        }
        .into_request()
        .expect("request should build")
    }

    #[test]
    fn verifies_matching_transfer_request() {
        let request = sample_request();

        let verified = verify_transfer_request(&request).expect("request should verify");

        assert_eq!(verified.request_id, request.id);
        assert_eq!(verified.signer_id, "alice.testnet");
        assert_eq!(verified.receiver_id, "bob.testnet");
        assert_eq!(verified.nonce, 42);
        assert_eq!(verified.deposit_yocto_near, "5");
    }

    #[test]
    fn rejects_mismatched_described_fields() {
        let mut request = sample_request();
        request.kind = TransactionKind::Transfer {
            signer_id: "mallory.testnet".to_owned(),
            signer_public_key: "ed25519:11111111111111111111111111111111".to_owned(),
            receiver_id: "bob.testnet".to_owned(),
            nonce: 42,
            block_hash: "11111111111111111111111111111111".to_owned(),
            deposit_yocto_near: "5".to_owned(),
        };

        let error = verify_transfer_request(&request).expect_err("request should be rejected");

        match error {
            AirgapError::RequestMismatch { field, .. } => assert_eq!(field, "signer_id"),
            other => panic!("unexpected error: {other}"),
        }
    }
}
