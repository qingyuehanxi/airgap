use argon2::{
    Algorithm, Argon2, ParamsBuilder, Version,
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};
use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, RwLock},
};
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone)]
pub enum PasswordError {
    InvalidLength,
    FoundInHibp,
    VerifyFailed,
    HashFailed(String),
    InvalidStoredHash(String),
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "password length must be between 12 and 1024 characters"),
            Self::FoundInHibp => write!(f, "password is found in HIBP"),
            Self::VerifyFailed => write!(f, "invalid session password"),
            Self::HashFailed(message) => write!(f, "{message}"),
            Self::InvalidStoredHash(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for PasswordError {}

#[derive(Default, Debug, Clone)]
pub struct PasswordPolicy {
    hibp_top10k: Arc<RwLock<HashSet<String>>>,
}

impl PasswordPolicy {
    pub fn from_hibp<I>(iter: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let hibp_set = iter.into_iter().map(|s| s.as_ref().nfc().collect::<String>()).collect();
        Self {
            hibp_top10k: Arc::new(RwLock::new(hibp_set)),
        }
    }

    pub fn from_text(opt_text: Option<&str>) -> Self {
        match opt_text {
            Some(text) => Self::from_hibp(text.lines().map(|line| line.trim()).filter(|s| !s.is_empty())),
            None => Self::default(),
        }
    }

    pub async fn validate_password(&self, password: &str) -> Result<(), PasswordError> {
        let password = normalize_password(password);
        if !(12..=1024).contains(&password.chars().count()) {
            return Err(PasswordError::InvalidLength);
        }

        let hibp_set = self
            .hibp_top10k
            .read()
            .map_err(|e| PasswordError::HashFailed(format!("failed to read password policy: {e}")))?;
        if hibp_set.contains(&password) {
            return Err(PasswordError::FoundInHibp);
        }

        Ok(())
    }

    pub async fn verify_password(password: &str, phc: &str) -> Result<(), PasswordError> {
        let password = normalize_password(password);
        let phc = phc.to_owned();

        let parsed_hash = PasswordHash::new(&phc)
            .map_err(|e| PasswordError::InvalidStoredHash(format!("stored vault verifier is invalid: {e}")))?;

        password_argon2()?
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(map_password_verify_error)
    }

    pub async fn hash_password(password: &str) -> Result<String, PasswordError> {
        let password = normalize_password(password);
        let salt = SaltString::generate(&mut OsRng);
        password_argon2()?
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| PasswordError::HashFailed(format!("failed to hash session password: {e}")))
    }
}

fn password_argon2() -> Result<Argon2<'static>, PasswordError> {
    let params = ParamsBuilder::new()
        .m_cost(19 * 1024)
        .t_cost(1)
        .p_cost(1)
        .build()
        .map_err(|e| PasswordError::HashFailed(format!("failed to configure password hasher: {e}")))?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn normalize_password(password: &str) -> String {
    password.nfc().collect::<String>()
}

fn map_password_verify_error(error: PasswordHashError) -> PasswordError {
    match error {
        PasswordHashError::Password => PasswordError::VerifyFailed,
        other => PasswordError::HashFailed(format!("failed to verify session password: {other}")),
    }
}
