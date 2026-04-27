use thiserror::Error;

#[derive(Debug, Error)]
pub enum AirgapError {
    #[error("invalid network, got {0}")]
    InvalidNetwork(String),
    #[error("invalid rpc provider, got {0}")]
    InvalidRpcProvider(String),
    #[error("{field} is not a valid NEAR account id: {value}")]
    InvalidAccountId {
        field: &'static str,
        value: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("signer_public_key is not a valid NEAR public key: {value}")]
    InvalidPublicKey {
        value: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("block_hash is not a valid NEAR block hash: {value}")]
    InvalidBlockHash {
        value: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("failed to serialize transaction: {0}")]
    Borsh(#[from] std::io::Error),
    #[error("failed to serialize request json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to decode base64: {0}")]
    Base64Decode(String),
    #[error("unsupported transaction: {0}")]
    UnsupportedTransaction(String),
    #[error("request field {field} does not match the transaction bytes (described: {described}, actual: {actual})")]
    RequestMismatch {
        field: &'static str,
        described: String,
        actual: String,
    },
}
