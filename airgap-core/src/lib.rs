pub mod cfg;
pub mod error;
pub mod util;

use crate::cfg::network::Network;
use base64::{Engine as _, engine::general_purpose::STANDARD};
pub use error::biz_error::AirgapError;
use near_crypto::PublicKey;
use near_primitives::{
    account::{AccessKey, AccessKeyPermission},
    hash::CryptoHash,
    transaction::{Action, AddKeyAction, DeleteKeyAction, Transaction, TransactionV0, TransferAction},
    types::{AccountId, Balance, Nonce},
};
use serde::{Deserialize, Serialize};
pub use util::password::{PasswordError, PasswordPolicy};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransactionRequest {
    pub id: String,
    pub network: Network,
    pub kind: TransactionKind,
    pub transaction_borsh_base64: String,
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
    DeleteKey {
        signer_id: String,
        signer_public_key: String,
        receiver_id: String,
        nonce: Nonce,
        block_hash: String,
        delete_public_key: String,
    },
    AddKey {
        signer_id: String,
        signer_public_key: String,
        receiver_id: String,
        nonce: Nonce,
        block_hash: String,
        add_public_key: String,
        permission: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransferRequest {
    pub request_id: String,
    pub network: Network,
    pub signer_id: String,
    pub signer_public_key: String,
    pub receiver_id: String,
    pub nonce: Nonce,
    pub block_hash: String,
    pub deposit_yocto_near: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeleteKeyRequest {
    pub request_id: String,
    pub network: Network,
    pub signer_id: String,
    pub signer_public_key: String,
    pub receiver_id: String,
    pub nonce: Nonce,
    pub block_hash: String,
    pub delete_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAddKeyRequest {
    pub request_id: String,
    pub network: Network,
    pub signer_id: String,
    pub signer_public_key: String,
    pub receiver_id: String,
    pub nonce: Nonce,
    pub block_hash: String,
    pub add_public_key: String,
    pub permission: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedRequest {
    Transfer(VerifiedTransferRequest),
    DeleteKey(VerifiedDeleteKeyRequest),
    AddKey(VerifiedAddKeyRequest),
}

#[derive(Debug, Clone)]
pub struct TransferDraft {
    pub network: Network,
    pub signer_id: String,
    pub signer_public_key: String,
    pub receiver_id: String,
    pub nonce: Nonce,
    pub block_hash: String,
    pub deposit_yocto_near: Balance,
}

#[derive(Debug, Clone)]
pub struct DeleteKeyDraft {
    pub network: Network,
    pub signer_id: String,
    pub signer_public_key: String,
    pub receiver_id: String,
    pub nonce: Nonce,
    pub block_hash: String,
    pub delete_public_key: String,
}

#[derive(Debug, Clone)]
pub struct AddKeyDraft {
    pub network: Network,
    pub signer_id: String,
    pub signer_public_key: String,
    pub receiver_id: String,
    pub nonce: Nonce,
    pub block_hash: String,
    pub add_public_key: String,
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

impl DeleteKeyDraft {
    pub fn into_request(self) -> Result<UnsignedTransactionRequest, AirgapError> {
        let transaction = Transaction::V0(TransactionV0 {
            signer_id: parse_account_id("signer_id", &self.signer_id)?,
            public_key: parse_public_key(&self.signer_public_key)?,
            nonce: self.nonce,
            receiver_id: parse_account_id("receiver_id", &self.receiver_id)?,
            block_hash: parse_block_hash(&self.block_hash)?,
            actions: vec![Action::DeleteKey(Box::new(DeleteKeyAction {
                public_key: parse_public_key(&self.delete_public_key)?,
            }))],
        });

        let transaction_borsh_base64 = STANDARD.encode(borsh::to_vec(&transaction)?);

        Ok(UnsignedTransactionRequest {
            id: Uuid::now_v7().to_string(),
            network: self.network,
            kind: TransactionKind::DeleteKey {
                signer_id: self.signer_id,
                signer_public_key: self.signer_public_key,
                receiver_id: self.receiver_id,
                nonce: self.nonce,
                block_hash: self.block_hash,
                delete_public_key: self.delete_public_key,
            },
            transaction_borsh_base64,
        })
    }
}

impl AddKeyDraft {
    pub fn into_request(self) -> Result<UnsignedTransactionRequest, AirgapError> {
        let transaction = Transaction::V0(TransactionV0 {
            signer_id: parse_account_id("signer_id", &self.signer_id)?,
            public_key: parse_public_key(&self.signer_public_key)?,
            nonce: self.nonce,
            receiver_id: parse_account_id("receiver_id", &self.receiver_id)?,
            block_hash: parse_block_hash(&self.block_hash)?,
            actions: vec![Action::AddKey(Box::new(AddKeyAction {
                public_key: parse_public_key(&self.add_public_key)?,
                access_key: AccessKey {
                    nonce: 0,
                    permission: AccessKeyPermission::FullAccess,
                },
            }))],
        });

        let transaction_borsh_base64 = STANDARD.encode(borsh::to_vec(&transaction)?);

        Ok(UnsignedTransactionRequest {
            id: Uuid::now_v7().to_string(),
            network: self.network,
            kind: TransactionKind::AddKey {
                signer_id: self.signer_id,
                signer_public_key: self.signer_public_key,
                receiver_id: self.receiver_id,
                nonce: self.nonce,
                block_hash: self.block_hash,
                add_public_key: self.add_public_key,
                permission: "FullAccess".to_owned(),
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
    match verify_request(request)? {
        VerifiedRequest::Transfer(verified) => Ok(verified),
        VerifiedRequest::DeleteKey(_) | VerifiedRequest::AddKey(_) => Err(AirgapError::UnsupportedTransaction(
            "expected a transfer request but got a non-transfer request".to_owned(),
        )),
    }
}

pub fn verify_request(request: &UnsignedTransactionRequest) -> Result<VerifiedRequest, AirgapError> {
    let (verified, _, _) = decode_and_verify_request(request)?;
    Ok(verified)
}

pub fn sign_request(
    request: &UnsignedTransactionRequest,
    secret_key: &near_crypto::SecretKey,
) -> Result<SignedTransactionResponse, AirgapError> {
    let (_, _, transaction) = decode_and_verify_request(request)?;
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

pub fn sign_transfer_request(
    request: &UnsignedTransactionRequest,
    secret_key: &near_crypto::SecretKey,
) -> Result<SignedTransactionResponse, AirgapError> {
    sign_request(request, secret_key)
}

fn decode_and_verify_request(
    request: &UnsignedTransactionRequest,
) -> Result<(VerifiedRequest, Vec<u8>, Transaction), AirgapError> {
    let bytes = STANDARD
        .decode(&request.transaction_borsh_base64)
        .map_err(|e| AirgapError::Base64Decode(e.to_string()))?;
    let transaction: Transaction = borsh::from_slice(&bytes)?;

    let transaction_v0 = match &transaction {
        Transaction::V0(transaction_v0) => transaction_v0,
        Transaction::V1(_) => {
            return Err(AirgapError::UnsupportedTransaction(
                "transaction version v1 is not supported".to_owned(),
            ));
        }
    };

    let verified = match (&request.kind, transaction_v0.actions.as_slice()) {
        (
            TransactionKind::Transfer {
                signer_id: described_signer_id,
                signer_public_key: described_signer_public_key,
                receiver_id: described_receiver_id,
                nonce: described_nonce,
                block_hash: described_block_hash,
                deposit_yocto_near: described_deposit,
            },
            [Action::Transfer(transfer)],
        ) => {
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

            VerifiedRequest::Transfer(verified)
        }
        (
            TransactionKind::DeleteKey {
                signer_id: described_signer_id,
                signer_public_key: described_signer_public_key,
                receiver_id: described_receiver_id,
                nonce: described_nonce,
                block_hash: described_block_hash,
                delete_public_key: described_delete_public_key,
            },
            [Action::DeleteKey(delete_key)],
        ) => {
            let verified = VerifiedDeleteKeyRequest {
                request_id: request.id.clone(),
                network: request.network,
                signer_id: transaction_v0.signer_id.to_string(),
                signer_public_key: transaction_v0.public_key.to_string(),
                receiver_id: transaction_v0.receiver_id.to_string(),
                nonce: transaction_v0.nonce,
                block_hash: transaction_v0.block_hash.to_string(),
                delete_public_key: delete_key.public_key.to_string(),
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
            ensure_matches(
                "delete_public_key",
                described_delete_public_key,
                &verified.delete_public_key,
            )?;

            VerifiedRequest::DeleteKey(verified)
        }
        (
            TransactionKind::AddKey {
                signer_id: described_signer_id,
                signer_public_key: described_signer_public_key,
                receiver_id: described_receiver_id,
                nonce: described_nonce,
                block_hash: described_block_hash,
                add_public_key: described_add_public_key,
                permission: described_permission,
            },
            [Action::AddKey(add_key)],
        ) => {
            let permission = match &add_key.access_key.permission {
                AccessKeyPermission::FullAccess => "FullAccess".to_owned(),
                AccessKeyPermission::FunctionCall(_) => {
                    return Err(AirgapError::UnsupportedTransaction(
                        "only full-access add-key transactions are supported".to_owned(),
                    ));
                }
            };

            let verified = VerifiedAddKeyRequest {
                request_id: request.id.clone(),
                network: request.network,
                signer_id: transaction_v0.signer_id.to_string(),
                signer_public_key: transaction_v0.public_key.to_string(),
                receiver_id: transaction_v0.receiver_id.to_string(),
                nonce: transaction_v0.nonce,
                block_hash: transaction_v0.block_hash.to_string(),
                add_public_key: add_key.public_key.to_string(),
                permission,
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
            ensure_matches("add_public_key", described_add_public_key, &verified.add_public_key)?;
            ensure_matches("permission", described_permission, &verified.permission)?;

            VerifiedRequest::AddKey(verified)
        }
        (TransactionKind::Transfer { .. }, _) => {
            return Err(AirgapError::UnsupportedTransaction(
                "only single-action transfer transactions are supported".to_owned(),
            ));
        }
        (TransactionKind::DeleteKey { .. }, _) => {
            return Err(AirgapError::UnsupportedTransaction(
                "only single-action delete-key transactions are supported".to_owned(),
            ));
        }
        (TransactionKind::AddKey { .. }, _) => {
            return Err(AirgapError::UnsupportedTransaction(
                "only single-action full-access add-key transactions are supported".to_owned(),
            ));
        }
    };

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
            network: Network::Testnet,
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

    #[test]
    fn verifies_matching_delete_key_request() {
        let request = DeleteKeyDraft {
            network: Network::Testnet,
            signer_id: "alice.testnet".to_owned(),
            signer_public_key: "ed25519:11111111111111111111111111111111".to_owned(),
            receiver_id: "alice.testnet".to_owned(),
            nonce: 42,
            block_hash: "11111111111111111111111111111111".to_owned(),
            delete_public_key: "ed25519:11111111111111111111111111111111".to_owned(),
        }
        .into_request()
        .expect("request should build");

        let verified = verify_request(&request).expect("request should verify");

        let VerifiedRequest::DeleteKey(verified) = verified else {
            panic!("expected a delete-key request");
        };

        assert_eq!(verified.request_id, request.id);
        assert_eq!(verified.signer_id, "alice.testnet");
        assert_eq!(verified.receiver_id, "alice.testnet");
        assert_eq!(verified.delete_public_key, "ed25519:11111111111111111111111111111111");
    }

    #[test]
    fn verifies_matching_add_key_request() {
        let request = AddKeyDraft {
            network: Network::Testnet,
            signer_id: "alice.testnet".to_owned(),
            signer_public_key: "ed25519:11111111111111111111111111111111".to_owned(),
            receiver_id: "alice.testnet".to_owned(),
            nonce: 42,
            block_hash: "11111111111111111111111111111111".to_owned(),
            add_public_key: "ed25519:11111111111111111111111111111111".to_owned(),
        }
        .into_request()
        .expect("request should build");

        let verified = verify_request(&request).expect("request should verify");

        let VerifiedRequest::AddKey(verified) = verified else {
            panic!("expected an add-key request");
        };

        assert_eq!(verified.request_id, request.id);
        assert_eq!(verified.signer_id, "alice.testnet");
        assert_eq!(verified.receiver_id, "alice.testnet");
        assert_eq!(verified.add_public_key, "ed25519:11111111111111111111111111111111");
        assert_eq!(verified.permission, "FullAccess");
    }
}
