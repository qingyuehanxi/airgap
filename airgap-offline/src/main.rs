use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use airgap_core::{
    PasswordPolicy, SignedTransactionResponse, UnsignedTransactionRequest, VerifiedRequest,
    cfg::language::SupportLanguage, request_from_json, response_to_pretty_json, sign_request, verify_request,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bip39::{Language, Mnemonic};
use bs58::encode as bs58_encode;
use ed25519_dalek::SigningKey;
use iced::{
    Alignment, Background, Border, Color, Element, Length, Task, clipboard,
    widget::{button, column, container, pick_list, row, scrollable, svg, text, text_input},
};
use near_crypto::SecretKey;
use near_primitives::types::AccountId;
use near_slip10::{BIP32Path, Curve, derive_key_from_path};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, str::FromStr};

const VAULT_SALT_KEY: &[u8] = b"vault_salt";
const VAULT_VERIFIER_KEY: &[u8] = b"vault_verifier";
const ACCOUNTS_DB_KEY: &[u8] = b"saved_accounts";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SAVED_ACCOUNT_COLUMN_WIDTH: f32 = 180.0;
const SAVED_MNEMONIC_COLUMN_WIDTH: f32 = 170.0;
const SAVED_ACTION_COLUMN_WIDTH: f32 = 96.0;
const COPY_ICON_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../asset/mingcute-copy.svg");
const DELETE_ICON_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../asset/mingcute-delete.svg");
const DEFAULT_SEED_PHRASE_HD_PATH: &str = "m/44'/397'/0'";
const SUPPORTED_LANGUAGES: [SupportLanguage; 2] = [SupportLanguage::English, SupportLanguage::Chinese];

fn main() -> iced::Result {
    iced::application(OfflineApp::default, OfflineApp::update, OfflineApp::view)
        .title("🔐 Airgap Offline")
        .window_size((1160.0, 760.0))
        .centered()
        .run()
}

fn db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".airgap").join("airgap-offline").join("db")
}

fn output_dir() -> PathBuf {
    db_path()
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(db_path)
        .join("out")
}

fn default_output_path() -> String {
    output_dir().join("transaction-signed.json").display().to_string()
}

fn default_request_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join(".airgap")
        .join("airgap-online")
        .join("out")
        .join("transaction-unsigned.json")
        .display()
        .to_string()
}

fn parse_output_path(value: &str) -> Result<PathBuf, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("output file is required".to_owned());
    }

    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(output_dir().join(path))
    }
}

#[derive(Debug, Clone)]
enum Message {
    UnlockPasswordChanged(String),
    UnlockPressed,
    UnlockFinished(Result<VaultSession, String>),
    BeginVaultResetPressed,
    CancelVaultResetPressed,
    ConfirmVaultResetPressed,
    TabSelected(Tab),
    LanguageChanged(SupportLanguage),
    AccountIdChanged(String),
    MnemonicChanged(String),
    SaveAccountPressed,
    RemoveAccountPressed { account_id: String, public_key: String },
    MnemonicLanguageSelected(MnemonicLanguage),
    GenerateMnemonicPressed,
    CopyPressed(String),
    LoadRequestPressed,
    RequestFileChanged(String),
    RequestLoaded(Result<LoadedRequest, String>),
    ConfirmAndSignPressed,
    Signed(Result<SignedTransactionResponse, String>),
    OutputChanged(String),
    ExportPressed,
    Exported(Result<PathBuf, String>),
    CurrentPasswordChanged(String),
    NewPasswordChanged(String),
    ConfirmNewPasswordChanged(String),
    ChangePasswordPressed,
    PasswordChanged(Result<(), String>),
    ResetPressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Sign,
    Accounts,
    Mnemonic,
    Password,
}

#[derive(Debug)]
enum AppScreen {
    Locked(LockedState),
    Unlocked(UnlockedState),
}

#[derive(Debug)]
struct LockedState {
    password: String,
    reset_confirmation_required: bool,
}

#[derive(Debug)]
struct UnlockedState {
    active_tab: Tab,
    language: SupportLanguage,
    session: VaultSession,
    account_id_input: String,
    mnemonic_input: String,
    mnemonic_language: MnemonicLanguage,
    generated_mnemonic: String,
    sign_state: SignState,
    request_file_path: String,
    output: String,
    current_password_input: String,
    new_password_input: String,
    confirm_new_password_input: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MnemonicLanguage {
    ChineseSimplified,
    English,
}

impl std::fmt::Display for MnemonicLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChineseSimplified => write!(f, "Simplified Chinese"),
            Self::English => write!(f, "English"),
        }
    }
}

#[derive(Debug)]
enum SignState {
    Idle,
    RequestLoaded(LoadedRequest),
    Signed(SignedTransactionResponse),
    Exported,
}

#[derive(Debug)]
enum Status {
    Idle,
    Warning(String),
    Error(String),
    Success(String),
}

#[derive(Debug, Clone)]
struct LoadedRequest {
    request: UnsignedTransactionRequest,
    verified: VerifiedRequest,
}

#[derive(Debug, Clone)]
struct VaultSession {
    encryption_key: [u8; KEY_LEN],
    accounts: Vec<UnlockedAccount>,
}

#[derive(Debug, Clone)]
struct UnlockedAccount {
    account_id: String,
    mnemonic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAccount {
    account_id: String,
    encrypted_mnemonic: EncryptedSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedSecret {
    nonce_base64: String,
    ciphertext_base64: String,
}

struct OfflineApp {
    db: sled::Db,
    screen: AppScreen,
    status: Status,
}

fn locked_state() -> LockedState {
    LockedState {
        password: String::new(),
        reset_confirmation_required: false,
    }
}

impl Default for OfflineApp {
    fn default() -> Self {
        let db = sled::open(db_path()).expect("failed to open key database");

        Self {
            db,
            screen: AppScreen::Locked(locked_state()),
            status: Status::Idle,
        }
    }
}

impl OfflineApp {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::UnlockPasswordChanged(value) => {
                if let AppScreen::Locked(locked) = &mut self.screen {
                    locked.password = value;
                    if matches!(self.status, Status::Error(_)) {
                        self.status = Status::Idle;
                    }
                }
            }
            Message::BeginVaultResetPressed => {
                if let AppScreen::Locked(locked) = &mut self.screen {
                    locked.reset_confirmation_required = true;
                    self.status = Status::Warning(
                        "Reset will permanently delete the local vault and all saved Keychain data.".to_owned(),
                    );
                }
            }
            Message::CancelVaultResetPressed => {
                if let AppScreen::Locked(locked) = &mut self.screen {
                    locked.reset_confirmation_required = false;
                    self.status = Status::Idle;
                }
            }
            Message::ConfirmVaultResetPressed => match reset_vault(&self.db) {
                Ok(()) => {
                    self.screen = AppScreen::Locked(locked_state());
                    self.status = Status::Success(
                        "Local vault deleted. You can now create a new session password and start fresh.".to_owned(),
                    );
                }
                Err(error) => self.status = Status::Error(error),
            },
            Message::UnlockPressed => {
                let password = match &self.screen {
                    AppScreen::Locked(locked) => locked.password.trim().to_owned(),
                    AppScreen::Unlocked(_) => return Task::none(),
                };
                let db = self.db.clone();
                self.status = Status::Success("Unlocking vault...".to_owned());
                return Task::perform(unlock_or_initialize_session(db, password), Message::UnlockFinished);
            }
            Message::UnlockFinished(result) => match result {
                Ok(session) => {
                    self.screen = AppScreen::Unlocked(UnlockedState {
                        active_tab: Tab::Sign,
                        language: SupportLanguage::English,
                        sign_state: SignState::Idle,
                        request_file_path: default_request_path(),
                        output: default_output_path(),
                        account_id_input: String::new(),
                        mnemonic_input: String::new(),
                        mnemonic_language: MnemonicLanguage::English,
                        generated_mnemonic: String::new(),
                        current_password_input: String::new(),
                        new_password_input: String::new(),
                        confirm_new_password_input: String::new(),
                        session,
                    });
                    self.status = Status::Success(
                        "Vault unlocked. Mnemonics are available in memory for this session.".to_owned(),
                    );
                }
                Err(error) => self.status = Status::Error(error),
            },
            Message::TabSelected(tab) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.active_tab = tab;
                    if matches!(self.status, Status::Success(_)) {
                        self.status = Status::Idle;
                    }
                }
            }
            Message::LanguageChanged(language) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.language = language;
                }
            }
            Message::AccountIdChanged(value) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.account_id_input = value;
                }
            }
            Message::MnemonicChanged(value) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.mnemonic_input = value;
                }
            }
            Message::SaveAccountPressed => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    match save_account(
                        &self.db,
                        &mut unlocked.session,
                        &unlocked.account_id_input,
                        &unlocked.mnemonic_input,
                    ) {
                        Ok(saved_account_id) => {
                            unlocked.account_id_input.clear();
                            unlocked.mnemonic_input.clear();
                            self.status = Status::Success(format!(
                                "Saved account {saved_account_id} and encrypted its mnemonic in sled."
                            ));
                        }
                        Err(error) => self.status = Status::Error(error),
                    }
                }
            }
            Message::RemoveAccountPressed { account_id, public_key } => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    match remove_account(&self.db, &mut unlocked.session, &account_id, &public_key) {
                        Ok(removed_account_id) => {
                            self.status = Status::Success(format!(
                                "Removed account {removed_account_id} from the offline keychain."
                            ));
                        }
                        Err(error) => self.status = Status::Error(error),
                    }
                }
            }
            Message::GenerateMnemonicPressed => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    match generate_mnemonic(unlocked.mnemonic_language) {
                        Ok(mnemonic) => {
                            unlocked.generated_mnemonic = mnemonic;
                            self.status = Status::Success(format!(
                                "Generated a new {} mnemonic offline.",
                                mnemonic_kind(unlocked.mnemonic_language)
                            ));
                        }
                        Err(error) => self.status = Status::Error(error),
                    }
                }
            }
            Message::MnemonicLanguageSelected(language) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.mnemonic_language = language;
                    if !unlocked.generated_mnemonic.is_empty() && matches!(self.status, Status::Success(_)) {
                        self.status =
                            Status::Success(format!("Generated a new {} mnemonic offline.", mnemonic_kind(language)));
                    }
                }
            }
            Message::CopyPressed(content) => {
                return clipboard::write(content);
            }
            Message::LoadRequestPressed => {
                let path = match &self.screen {
                    AppScreen::Unlocked(unlocked) => unlocked.request_file_path.trim().to_owned(),
                    AppScreen::Locked(_) => return Task::none(),
                };
                return Task::perform(load_request(path), Message::RequestLoaded);
            }
            Message::RequestFileChanged(value) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.request_file_path = value;
                }
            }
            Message::RequestLoaded(result) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    match result {
                        Ok(request) => {
                            unlocked.sign_state = SignState::RequestLoaded(request);
                            self.status =
                                Status::Success("Request verified against the real transaction bytes.".to_owned());
                        }
                        Err(error) => self.status = Status::Error(error),
                    }
                }
            }
            Message::ConfirmAndSignPressed => {
                let request = match &self.screen {
                    AppScreen::Unlocked(unlocked) => match &unlocked.sign_state {
                        SignState::RequestLoaded(loaded) => loaded.request.clone(),
                        _ => return Task::none(),
                    },
                    AppScreen::Locked(_) => return Task::none(),
                };
                let accounts = match &self.screen {
                    AppScreen::Unlocked(unlocked) => unlocked.session.accounts.clone(),
                    AppScreen::Locked(_) => {
                        self.status = Status::Error("vault is locked".to_owned());
                        return Task::none();
                    }
                };
                let secret_key = match find_signing_key(&accounts, &request) {
                    Ok(key) => key,
                    Err(error) => {
                        self.status = Status::Error(error);
                        return Task::none();
                    }
                };
                return Task::perform(
                    async move { sign_request(&request, &secret_key).map_err(|e| e.to_string()) },
                    Message::Signed,
                );
            }
            Message::Signed(result) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    match result {
                        Ok(response) => {
                            unlocked.sign_state = SignState::Signed(response);
                            self.status = Status::Success("Transaction signed successfully.".to_owned());
                        }
                        Err(error) => self.status = Status::Error(error),
                    }
                }
            }
            Message::OutputChanged(value) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.output = value;
                }
            }
            Message::CurrentPasswordChanged(value) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.current_password_input = value;
                }
            }
            Message::NewPasswordChanged(value) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.new_password_input = value;
                }
            }
            Message::ConfirmNewPasswordChanged(value) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.confirm_new_password_input = value;
                }
            }
            Message::ChangePasswordPressed => {
                let (current_password, new_password, confirm_new_password) = match &self.screen {
                    AppScreen::Unlocked(unlocked) => (
                        unlocked.current_password_input.trim().to_owned(),
                        unlocked.new_password_input.trim().to_owned(),
                        unlocked.confirm_new_password_input.trim().to_owned(),
                    ),
                    AppScreen::Locked(_) => return Task::none(),
                };
                let db = self.db.clone();
                self.status = Status::Success("Migrating vault to the new password...".to_owned());
                return Task::perform(
                    change_vault_password(db, current_password, new_password, confirm_new_password),
                    Message::PasswordChanged,
                );
            }
            Message::PasswordChanged(result) => match result {
                Ok(()) => {
                    self.screen = AppScreen::Locked(locked_state());
                    self.status =
                        Status::Success("Password updated and vault re-encrypted. Please log in again.".to_owned());
                }
                Err(error) => self.status = Status::Error(error),
            },
            Message::ExportPressed => {
                let (response, output) = match &self.screen {
                    AppScreen::Unlocked(unlocked) => match &unlocked.sign_state {
                        SignState::Signed(response) => {
                            let output = match parse_output_path(&unlocked.output) {
                                Ok(path) => path,
                                Err(error) => {
                                    self.status = Status::Error(error);
                                    return Task::none();
                                }
                            };
                            (response.clone(), output)
                        }
                        _ => return Task::none(),
                    },
                    AppScreen::Locked(_) => return Task::none(),
                };
                return Task::perform(export_response(response, output), Message::Exported);
            }
            Message::Exported(result) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    match result {
                        Ok(path) => {
                            let _ = path;
                            unlocked.sign_state = SignState::Exported;
                            self.status = Status::Success("Signed response exported.".to_owned());
                        }
                        Err(error) => self.status = Status::Error(error),
                    }
                }
            }
            Message::ResetPressed => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.sign_state = SignState::Idle;
                    self.status = Status::Idle;
                }
            }
        }

        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        match &self.screen {
            AppScreen::Locked(locked) => locked_view(locked, &self.status),
            AppScreen::Unlocked(unlocked) => unlocked_view(unlocked, &self.status),
        }
    }
}

fn locked_view<'a>(locked: &'a LockedState, status: &'a Status) -> Element<'a, Message> {
    let reset_controls: Element<'a, Message> = if locked.reset_confirmation_required {
        row![
            button(
                container(text("Cancel").size(14))
                    .width(Length::Fill)
                    .center_x(Length::Fill)
            )
            .padding([10, 18])
            .width(Length::Fixed(150.0))
            .on_press(Message::CancelVaultResetPressed),
            button(
                container(text("Confirm Reset").size(14))
                    .width(Length::Fill)
                    .center_x(Length::Fill)
            )
            .padding([10, 18])
            .width(Length::Fixed(150.0))
            .on_press(Message::ConfirmVaultResetPressed),
        ]
        .spacing(10)
        .into()
    } else {
        button(
            container(text("Reset").size(14))
                .width(Length::Fill)
                .center_x(Length::Fill),
        )
        .padding([10, 18])
        .width(Length::Fixed(150.0))
        .on_press(Message::BeginVaultResetPressed)
        .into()
    };

    let content = container(
        column![
            section_heading(
                "Unlock offline vault",
                "Enter the session password to decrypt stored mnemonics into memory for this air-gapped signing session."
            ),
            column![
                text("Session password").size(14),
                text_input("Session password", &locked.password)
                    .on_input(Message::UnlockPasswordChanged)
                    .secure(true)
                    .padding(12)
                    .size(16)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .width(Length::Fill),
            row![
                reset_controls,
                button(container(text("Unlock").size(14)).width(Length::Fill).center_x(Length::Fill))
                    .padding([10, 18])
                    .width(Length::Fixed(150.0))
                    .on_press(Message::UnlockPressed),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            status_view(status),
        ]
        .spacing(24)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .max_width(720)
    .style(|_| card_style());

    let shell = column![
        top_bar(None),
        container(content).center_x(Length::Fill).center_y(Length::Fill)
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .spacing(0);

    container(shell)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(|_| iced::widget::container::Style {
            background: Some(Background::Color(Color::from_rgb8(247, 248, 252))),
            ..Default::default()
        })
        .into()
}

fn unlocked_view<'a>(unlocked: &'a UnlockedState, status: &'a Status) -> Element<'a, Message> {
    let shell = column![top_bar(Some(unlocked.language)), main_view(unlocked, status)]
        .width(Length::Fill)
        .height(Length::Fill)
        .spacing(0);

    container(shell)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(|_| iced::widget::container::Style {
            background: Some(Background::Color(Color::from_rgb8(247, 248, 252))),
            ..Default::default()
        })
        .into()
}

fn main_view<'a>(unlocked: &'a UnlockedState, status: &'a Status) -> Element<'a, Message> {
    let hero = hero_section(unlocked.active_tab);
    let tabs = tab_strip(unlocked.active_tab);
    let body = match unlocked.active_tab {
        Tab::Sign => signing_tab(unlocked),
        Tab::Accounts => accounts_tab(unlocked),
        Tab::Mnemonic => mnemonic_tab(unlocked),
        Tab::Password => password_tab(unlocked),
    };

    scrollable(
        container(
            container(
                column![hero, tabs, body, status_view(status)]
                    .spacing(24)
                    .width(Length::Fill),
            )
            .width(Length::Fill)
            .max_width(1120),
        )
        .width(Length::Fill)
        .padding([28, 32])
        .center_x(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn accounts_tab<'a>(unlocked: &'a UnlockedState) -> Element<'a, Message> {
    let accounts: Element<'a, Message> = if unlocked.session.accounts.is_empty() {
        column![text("No accounts saved yet. Add an account and encrypted mnemonic below.").size(14)].into()
    } else {
        saved_accounts_table(&unlocked.session.accounts)
    };

    container(
        column![
            section_heading(
                "Offline keychain",
                "Encrypt mnemonics in local storage and unlock them only for the current signing session."
            ),
            row![
                field("Account", &unlocked.account_id_input, Message::AccountIdChanged),
                multiline_field(
                    "Mnemonic / Seed Phrase",
                    &unlocked.mnemonic_input,
                    Message::MnemonicChanged
                ),
            ]
            .spacing(16),
            button(text("Save Account").size(16))
                .padding([12, 18])
                .on_press(Message::SaveAccountPressed),
            accounts,
        ]
        .spacing(20)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn mnemonic_tab<'a>(unlocked: &'a UnlockedState) -> Element<'a, Message> {
    let generated_view: Element<'a, Message> = if unlocked.generated_mnemonic.is_empty() {
        text("No mnemonic generated yet.").size(14).into()
    } else {
        let generated_public_key = derive_public_key_from_mnemonic(&unlocked.generated_mnemonic).ok();
        let generated_public_key_text = generated_public_key
            .clone()
            .unwrap_or_else(|| "Unable to derive public key".to_owned());
        let mut copy_public_key_button = copy_icon_button();
        if let Some(public_key) = generated_public_key.clone() {
            copy_public_key_button = copy_public_key_button.on_press(Message::CopyPressed(public_key));
        }
        column![
            text("Generated Mnemonic").size(18),
            row![
                container(text(unlocked.generated_mnemonic.as_str()).size(16))
                    .padding(16)
                    .width(Length::Fill),
                copy_icon_button().on_press(Message::CopyPressed(unlocked.generated_mnemonic.clone())),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            text("Derived Public Key").size(18),
            row![
                container(text(generated_public_key_text).size(16))
                    .padding(16)
                    .width(Length::Fill),
                copy_public_key_button,
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            text(mnemonic_safety_hint()).size(13),
        ]
        .spacing(12)
        .into()
    };

    container(
        column![
            section_heading(
                "Mnemonic generator",
                "Create a fresh 12-word mnemonic offline and move it directly into your secure storage workflow."
            ),
            text(mnemonic_generator_hint(unlocked.mnemonic_language)).size(14),
            column![
                text("Language").size(14),
                pick_list(
                    [MnemonicLanguage::ChineseSimplified, MnemonicLanguage::English],
                    Some(unlocked.mnemonic_language),
                    Message::MnemonicLanguageSelected
                )
                .width(Length::Fill),
            ]
            .spacing(8),
            button(text("Generate Mnemonic").size(16))
                .padding([12, 18])
                .on_press(Message::GenerateMnemonicPressed),
            generated_view,
        ]
        .spacing(20)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn saved_accounts_table(accounts: &[UnlockedAccount]) -> Element<'_, Message> {
    let header = row![
        container(text("Account").size(14)).width(SAVED_ACCOUNT_COLUMN_WIDTH),
        container(text("Mnemonic").size(14)).width(SAVED_MNEMONIC_COLUMN_WIDTH),
        container(text("Public Key").size(14)).width(Length::Fill),
        container(text("Action").size(14)).width(SAVED_ACTION_COLUMN_WIDTH),
    ]
    .spacing(16)
    .align_y(Alignment::Center);

    let rows = accounts.iter().fold(
        column![table_divider(), header, table_divider()].spacing(10),
        |column, account| column.push(saved_account_row(account)),
    );

    column![text("Saved Accounts").size(18), rows]
        .spacing(12)
        .width(Length::Fill)
        .into()
}

fn saved_account_row(account: &UnlockedAccount) -> Element<'_, Message> {
    let public_key = derive_public_key(account);

    column![
        row![
            container(text(&account.account_id).size(15)).width(SAVED_ACCOUNT_COLUMN_WIDTH),
            container(text(mask_mnemonic(&account.mnemonic)).size(13)).width(SAVED_MNEMONIC_COLUMN_WIDTH),
            container(text(short_public_key(&public_key)).size(13)).width(Length::Fill),
            container(
                button(
                    svg(svg::Handle::from_path(DELETE_ICON_PATH))
                        .width(Length::Fixed(16.0))
                        .height(Length::Fixed(16.0))
                )
                .padding([6, 10])
                .style(iced::widget::button::text)
                .on_press(Message::RemoveAccountPressed {
                    account_id: account.account_id.clone(),
                    public_key: public_key.clone(),
                })
            )
            .width(SAVED_ACTION_COLUMN_WIDTH),
        ]
        .spacing(16)
        .align_y(Alignment::Center),
        table_divider(),
    ]
    .spacing(10)
    .into()
}

fn short_public_key(value: &str) -> String {
    const PREFIX: &str = "ed25519:";
    if let Some(raw) = value.strip_prefix(PREFIX) {
        let char_count = raw.chars().count();
        if char_count > 10 {
            let start: String = raw.chars().take(5).collect();
            let end: String = raw
                .chars()
                .rev()
                .take(5)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            return format!("{PREFIX}{start}...{end}");
        }
    }

    value.to_owned()
}

fn table_divider() -> Element<'static, Message> {
    container(text(""))
        .width(Length::Fill)
        .height(1)
        .style(|_| iced::widget::container::Style {
            border: Border {
                width: 0.0,
                radius: 0.0.into(),
                color: Color::TRANSPARENT,
            },
            background: Some(Color::from_rgb8(229, 231, 235).into()),
            text_color: None,
            shadow: iced::Shadow::default(),
            snap: false,
        })
        .into()
}

fn signing_tab<'a>(unlocked: &'a UnlockedState) -> Element<'a, Message> {
    container(
        column![
            section_heading(
                "Sign offline request",
                "Review transfer or key-management requests from the online machine, match them against your offline keychain, then export the signed response."
            ),
            signing_keychain_view(&unlocked.session, &unlocked.sign_state),
            signing_section(&unlocked.sign_state, &unlocked.request_file_path, &unlocked.output),
            actions_row(&unlocked.sign_state),
        ]
        .spacing(24)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn password_tab<'a>(unlocked: &'a UnlockedState) -> Element<'a, Message> {
    container(
        column![
            section_heading(
                "Change vault password",
                "Use the current password to unlock existing data, then migrate all saved keychain mnemonics to a new password."
            ),
            field_secure("Current password", &unlocked.current_password_input, Message::CurrentPasswordChanged),
            field_secure("New password", &unlocked.new_password_input, Message::NewPasswordChanged),
            field_secure(
                "Confirm new password",
                &unlocked.confirm_new_password_input,
                Message::ConfirmNewPasswordChanged
            ),
            text("After the migration finishes, the app will return to the login screen and require the new password.")
                .size(13)
                .color(Color::from_rgb8(95, 103, 120)),
            button(container(text("Change Password").size(14)).width(Length::Fill).center_x(Length::Fill))
                .padding([10, 18])
                .width(Length::Fixed(220.0))
                .on_press(Message::ChangePasswordPressed),
        ]
        .spacing(18)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn signing_keychain_view<'a>(session: &'a VaultSession, sign_state: &'a SignState) -> Element<'a, Message> {
    let helper = match sign_state {
        SignState::RequestLoaded(loaded) => {
            let signer = verified_signer_id(&loaded.verified);
            if session.accounts.iter().any(|account| account.account_id == *signer) {
                format!("Keychain contains {signer}. Signing will derive its key from the stored mnemonic.")
            } else {
                format!("No Keychain entry matches signer {signer}. Add that account in Keychain before signing.")
            }
        }
        _ => "Signing keys are derived from Keychain mnemonics. No private key file import is needed.".to_owned(),
    };

    column![text("Signing Keychain").size(20), text(helper).size(14),]
        .spacing(8)
        .into()
}

fn signing_section<'a>(sign_state: &'a SignState, request_file_path: &'a str, output: &'a str) -> Element<'a, Message> {
    let mut sections: Vec<Element<'a, Message>> = vec![];

    sections.push(
        column![
            text("Request File").size(16),
            row![
                text_input("Request file path", request_file_path)
                    .on_input(Message::RequestFileChanged)
                    .padding(12)
                    .size(16)
                    .width(Length::Fill),
                button(text("Load").size(14))
                    .padding([8, 16])
                    .on_press(Message::LoadRequestPressed),
            ]
            .spacing(12),
        ]
        .spacing(12)
        .into(),
    );

    match sign_state {
        SignState::Idle => {
            sections.push(text("Load a request file to begin.").size(14).into());
        }
        SignState::RequestLoaded(loaded) => {
            sections.push(transaction_details_view(&loaded.verified));
        }
        SignState::Exported => {}
        SignState::Signed(_) => {}
    }

    sections.push(
        column![
            text("Output File").size(16),
            text_input("Output file", output)
                .on_input(Message::OutputChanged)
                .padding(12)
                .size(16)
                .width(Length::Fill),
        ]
        .spacing(12)
        .into(),
    );

    if let SignState::Signed(response) = sign_state {
        sections.push(signed_details_view(response));
    }

    column(sections).spacing(24).into()
}

fn transaction_details_view(request: &VerifiedRequest) -> Element<'_, Message> {
    let details = match request {
        VerifiedRequest::Transfer(request) => column![
            detail_row("Type".into(), "Transfer".to_owned()),
            detail_row("Network".into(), request.network.to_string()),
            detail_row("Signer".into(), request.signer_id.clone()),
            detail_row("Signer Public Key".into(), request.signer_public_key.clone()),
            detail_row("Receiver".into(), request.receiver_id.clone()),
            detail_row("Nonce".into(), request.nonce.to_string()),
            detail_row("Recent Block Hash".into(), request.block_hash.clone()),
            detail_row("Deposit".into(), format_near_amount(&request.deposit_yocto_near)),
            detail_row("Request ID".into(), request.request_id.clone()),
        ]
        .spacing(8),
        VerifiedRequest::DeleteKey(request) => column![
            detail_row("Type".into(), "DeleteKey".to_owned()),
            detail_row("Network".into(), request.network.to_string()),
            detail_row("Signer".into(), request.signer_id.clone()),
            detail_row("Signer Public Key".into(), request.signer_public_key.clone()),
            detail_row("Account".into(), request.receiver_id.clone()),
            detail_row("Delete Public Key".into(), request.delete_public_key.clone()),
            detail_row("Nonce".into(), request.nonce.to_string()),
            detail_row("Recent Block Hash".into(), request.block_hash.clone()),
            detail_row("Request ID".into(), request.request_id.clone()),
        ]
        .spacing(8),
        VerifiedRequest::AddKey(request) => column![
            detail_row("Type".into(), "AddKey".to_owned()),
            detail_row("Network".into(), request.network.to_string()),
            detail_row("Signer".into(), request.signer_id.clone()),
            detail_row("Signer Public Key".into(), request.signer_public_key.clone()),
            detail_row("Account".into(), request.receiver_id.clone()),
            detail_row("Add Public Key".into(), request.add_public_key.clone()),
            detail_row("Permission".into(), request.permission.clone()),
            detail_row("Nonce".into(), request.nonce.to_string()),
            detail_row("Recent Block Hash".into(), request.block_hash.clone()),
            detail_row("Request ID".into(), request.request_id.clone()),
        ]
        .spacing(8),
    };

    info_card("Transaction Details", details).into()
}

fn signed_details_view(response: &SignedTransactionResponse) -> Element<'_, Message> {
    let details = column![
        detail_row("Request ID".into(), response.request_id.clone()),
        detail_row("Public Key".into(), response.public_key.clone()),
        detail_row("Signature".into(), response.signature.clone()),
    ]
    .spacing(8);

    info_card("Signed Response", details).into()
}

fn info_card<'a>(
    title: &'static str,
    content: impl Into<Element<'a, Message>>,
) -> iced::widget::Container<'a, Message> {
    container(
        column![text(title).size(16), content.into()]
            .spacing(12)
            .width(Length::Fill),
    )
    .padding(16)
    .width(Length::Fill)
    .style(|_| iced::widget::container::Style {
        border: Border {
            width: 1.0,
            radius: 10.0.into(),
            color: Color::from_rgb8(59, 130, 246),
        },
        background: Some(Color::from_rgb8(239, 246, 255).into()),
        text_color: None,
        shadow: iced::Shadow::default(),
        snap: false,
    })
}

fn actions_row(sign_state: &SignState) -> Element<'_, Message> {
    let mut actions = row![].spacing(16).align_y(Alignment::Center);

    match sign_state {
        SignState::RequestLoaded(_) => {
            actions = actions.push(
                button(text("Confirm and Sign").size(16))
                    .padding([12, 18])
                    .on_press(Message::ConfirmAndSignPressed),
            );
        }
        SignState::Signed(_) => {
            actions = actions.push(
                button(text("Save").size(16))
                    .padding([12, 18])
                    .on_press(Message::ExportPressed),
            );
        }
        SignState::Exported | SignState::Idle => {
            actions = actions.push(
                button(text("Reset").size(14))
                    .padding([8, 16])
                    .on_press(Message::ResetPressed),
            );
        }
    }

    actions.into()
}

fn find_signing_key(accounts: &[UnlockedAccount], request: &UnsignedTransactionRequest) -> Result<SecretKey, String> {
    let verified = verify_request(request).map_err(|e| e.to_string())?;
    let signer_id = verified_signer_id(&verified);
    let signer_public_key = verified_signer_public_key(&verified);
    let matching_accounts: Vec<&UnlockedAccount> = accounts
        .iter()
        .filter(|account| account.account_id == *signer_id)
        .collect();

    if matching_accounts.is_empty() {
        return Err(format!("no Keychain account matches signer {signer_id}"));
    }

    matching_accounts
        .into_iter()
        .find_map(|account| {
            let secret_key = derive_secret_key(account);
            let derived_public_key = secret_key.public_key().to_string();
            (derived_public_key == *signer_public_key).then_some(secret_key)
        })
        .ok_or_else(|| {
            format!(
                "no saved mnemonic for {} derives the expected public key {}",
                signer_id, signer_public_key
            )
        })
}

fn verified_signer_id(request: &VerifiedRequest) -> &String {
    match request {
        VerifiedRequest::Transfer(request) => &request.signer_id,
        VerifiedRequest::DeleteKey(request) => &request.signer_id,
        VerifiedRequest::AddKey(request) => &request.signer_id,
    }
}

fn verified_signer_public_key(request: &VerifiedRequest) -> &String {
    match request {
        VerifiedRequest::Transfer(request) => &request.signer_public_key,
        VerifiedRequest::DeleteKey(request) => &request.signer_public_key,
        VerifiedRequest::AddKey(request) => &request.signer_public_key,
    }
}

fn derive_secret_key(account: &UnlockedAccount) -> SecretKey {
    derive_secret_key_from_mnemonic(account.mnemonic.trim())
        .expect("stored mnemonic should derive a valid NEAR secret key")
}

fn derive_public_key(account: &UnlockedAccount) -> String {
    derive_secret_key(account).public_key().to_string()
}

fn derive_public_key_from_mnemonic(mnemonic: &str) -> Result<String, String> {
    Ok(derive_secret_key_from_mnemonic(mnemonic)?.public_key().to_string())
}

fn derive_secret_key_from_mnemonic(mnemonic: &str) -> Result<SecretKey, String> {
    let normalized_mnemonic = normalize_mnemonic(mnemonic);
    let master_seed = Mnemonic::parse(&normalized_mnemonic)
        .map_err(|error| format!("mnemonic is invalid: {error}"))?
        .to_seed("");
    let hd_path = BIP32Path::from_str(DEFAULT_SEED_PHRASE_HD_PATH)
        .map_err(|error| format!("invalid default seed phrase HD path: {error}"))?;
    let derived_private_key = derive_key_from_path(&master_seed, Curve::Ed25519, &hd_path)
        .map_err(|error| format!("failed to derive a key from the mnemonic: {error}"))?;
    let signing_key = SigningKey::from_bytes(&derived_private_key.key);
    let secret_key_str = format!("ed25519:{}", bs58_encode(signing_key.to_keypair_bytes()).into_string());

    SecretKey::from_str(&secret_key_str).map_err(|error| format!("failed to parse derived secret key: {error}"))
}

fn normalize_mnemonic(mnemonic: &str) -> String {
    mnemonic
        .trim()
        .split_whitespace()
        .map(|part| part.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn generate_mnemonic(language: MnemonicLanguage) -> Result<String, String> {
    let bip39_language = match language {
        MnemonicLanguage::ChineseSimplified => Language::SimplifiedChinese,
        MnemonicLanguage::English => Language::English,
    };

    Mnemonic::generate_in(bip39_language, 12)
        .map(|mnemonic| mnemonic.to_string())
        .map_err(|error| format!("failed to generate mnemonic: {error}"))
}

fn mnemonic_safety_hint() -> &'static str {
    "Write it down offline and keep it somewhere safe. Do not screenshot, photograph, or transmit it online."
}

fn mnemonic_generator_hint(language: MnemonicLanguage) -> &'static str {
    match language {
        MnemonicLanguage::ChineseSimplified => "Generate a new offline mnemonic with 12 simplified Chinese words.",
        MnemonicLanguage::English => "Generate a new offline mnemonic with 12 English words.",
    }
}

fn mnemonic_kind(language: MnemonicLanguage) -> &'static str {
    match language {
        MnemonicLanguage::ChineseSimplified => "12-word simplified Chinese mnemonic",
        MnemonicLanguage::English => "12-word English mnemonic",
    }
}

fn field<'a>(label: &'static str, value: &'a str, on_input: fn(String) -> Message) -> Element<'a, Message> {
    column![
        text(label).size(14),
        text_input(label, value)
            .on_input(on_input)
            .padding(12)
            .size(16)
            .width(Length::Fill),
    ]
    .spacing(8)
    .width(Length::Fill)
    .into()
}

fn copy_icon_button<'a>() -> iced::widget::Button<'a, Message> {
    button(
        svg(svg::Handle::from_path(COPY_ICON_PATH))
            .width(Length::Fixed(16.0))
            .height(Length::Fixed(16.0)),
    )
    .padding([10, 16])
    .style(|theme, status| {
        let mut style = iced::widget::button::text(theme, status);
        style.background = match status {
            button::Status::Hovered => Some(Background::Color(Color::from_rgba8(99, 102, 241, 0.08))),
            button::Status::Pressed => Some(Background::Color(Color::from_rgba8(99, 102, 241, 0.16))),
            _ => None,
        };
        style.border = Border {
            width: 1.0,
            radius: 10.0.into(),
            color: if matches!(status, button::Status::Pressed) {
                Color::from_rgba8(99, 102, 241, 0.28)
            } else {
                Color::TRANSPARENT
            },
        };
        style
    })
}

fn field_secure<'a>(label: &'static str, value: &'a str, on_input: fn(String) -> Message) -> Element<'a, Message> {
    column![
        text(label).size(14),
        text_input(label, value)
            .on_input(on_input)
            .secure(true)
            .padding(12)
            .size(16)
            .width(Length::Fill),
    ]
    .spacing(8)
    .width(Length::Fill)
    .into()
}

fn multiline_field<'a>(label: &'static str, value: &'a str, on_input: fn(String) -> Message) -> Element<'a, Message> {
    column![
        text(label).size(14),
        text_input(label, value)
            .on_input(on_input)
            .padding(12)
            .size(16)
            .width(Length::Fill),
    ]
    .spacing(8)
    .width(Length::Fill)
    .into()
}

fn status_view(status: &Status) -> Element<'_, Message> {
    match status {
        Status::Idle => container(text("")).into(),
        Status::Success(msg) => container(text(msg).size(14))
            .padding(14)
            .width(Length::Fill)
            .style(|_| iced::widget::container::Style {
                border: Border {
                    width: 1.0,
                    radius: 10.0.into(),
                    color: Color::from_rgb8(34, 197, 94),
                },
                background: Some(Color::from_rgb8(240, 253, 244).into()),
                text_color: Some(Color::from_rgb8(22, 101, 52)),
                shadow: iced::Shadow::default(),
                snap: false,
            })
            .into(),
        Status::Warning(msg) => container(text(msg).size(14))
            .padding(14)
            .width(Length::Fill)
            .style(|_| iced::widget::container::Style {
                border: Border {
                    width: 1.0,
                    radius: 10.0.into(),
                    color: Color::from_rgb8(245, 158, 11),
                },
                background: Some(Color::from_rgb8(255, 251, 235).into()),
                text_color: Some(Color::from_rgb8(146, 64, 14)),
                shadow: iced::Shadow::default(),
                snap: false,
            })
            .into(),
        Status::Error(error) => container(text(format!("Error: {error}")).size(14))
            .padding(14)
            .width(Length::Fill)
            .style(|_| iced::widget::container::Style {
                border: Border {
                    width: 1.0,
                    radius: 10.0.into(),
                    color: Color::from_rgb8(239, 68, 68),
                },
                background: Some(Color::from_rgb8(254, 242, 242).into()),
                text_color: Some(Color::from_rgb8(153, 27, 27)),
                shadow: iced::Shadow::default(),
                snap: false,
            })
            .into(),
    }
}

fn detail_row(label: String, value: String) -> Element<'static, Message> {
    row![text(label).size(14), text(value).size(14)].spacing(12).into()
}

fn top_bar(language: Option<SupportLanguage>) -> Element<'static, Message> {
    let spacer = container(text("")).width(Length::Fill);
    let title = row![
        container(
            container(text("🔐").size(18))
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
        )
        .width(40)
        .height(40)
        .style(|_| iced::widget::container::Style {
            border: Border {
                width: 2.0,
                radius: 999.0.into(),
                color: Color::from_rgb8(139, 92, 246),
            },
            ..Default::default()
        }),
        column![
            text("Airgap Offline").size(24),
            text("Cold machine").size(13).color(Color::from_rgb8(107, 114, 128))
        ]
        .spacing(2)
    ]
    .spacing(14)
    .align_y(Alignment::Center);

    let trailing: Element<'static, Message> = match language {
        Some(selected_language) => topbar_picker(
            &SUPPORTED_LANGUAGES,
            Some(selected_language),
            Message::LanguageChanged,
            160.0,
        ),
        None => container(text("Vault locked").size(13).color(Color::from_rgb8(107, 114, 128)))
            .padding([8, 0])
            .into(),
    };

    container(row![title, spacer, trailing].spacing(16).align_y(Alignment::Center))
        .padding([20, 28])
        .width(Length::Fill)
        .style(|_| iced::widget::container::Style {
            background: Some(Background::Color(Color::WHITE)),
            ..Default::default()
        })
        .into()
}

fn hero_section(active_tab: Tab) -> Element<'static, Message> {
    let (eyebrow, title, subtitle) = match active_tab {
        Tab::Sign => (
            "OFFLINE SIGNING",
            "Verify requests and sign transactions in an isolated flow",
            "Bring in the unsigned request, verify every field against the transaction bytes, then export the signed response back to the online machine.",
        ),
        Tab::Accounts => (
            "OFFLINE KEYCHAIN",
            "Keep saved mnemonics encrypted until the session is unlocked",
            "Store account mnemonics locally, decrypt them only in memory for the active session, and derive signing keys when needed.",
        ),
        Tab::Mnemonic => (
            "MNEMONIC LAB",
            "Generate fresh recovery phrases fully offline",
            "Create 12-word phrases without touching the network, then move them into your secure backup and vault workflow.",
        ),
        Tab::Password => (
            "VAULT PASSWORD",
            "Rotate your session password and migrate encrypted history safely",
            "Verify the current password, re-encrypt all saved keychain mnemonics with the new password, then return to the login screen.",
        ),
    };

    container(
        column![
            text(eyebrow).size(13).color(Color::from_rgb8(72, 110, 255)),
            text(title).size(36),
            text(subtitle).size(16).color(Color::from_rgb8(95, 103, 120)),
        ]
        .spacing(10)
        .max_width(760),
    )
    .padding([32, 36])
    .width(Length::Fill)
    .style(|_| iced::widget::container::Style {
        background: Some(Background::Color(Color::from_rgb8(240, 244, 255))),
        border: Border {
            width: 1.0,
            radius: 24.0.into(),
            color: Color::from_rgb8(220, 228, 255),
        },
        ..Default::default()
    })
    .into()
}

fn tab_strip(active_tab: Tab) -> Element<'static, Message> {
    container(
        row![
            top_tab_button("Sign", Tab::Sign, active_tab),
            top_tab_button("Mnemonic", Tab::Mnemonic, active_tab),
            top_tab_button("Keychain", Tab::Accounts, active_tab),
            top_tab_button("Password", Tab::Password, active_tab),
        ]
        .spacing(12)
        .align_y(Alignment::Center),
    )
    .width(Length::Shrink)
    .into()
}

fn top_tab_button<'a>(label: &'static str, tab: Tab, active_tab: Tab) -> Element<'a, Message> {
    let is_active = tab == active_tab;
    let mut tab_button = button(text(label).size(15))
        .padding([10, 18])
        .style(move |theme, status| {
            if is_active {
                button::primary(theme, status)
            } else {
                button::secondary(theme, status)
            }
        });
    if !is_active {
        tab_button = tab_button.on_press(Message::TabSelected(tab));
    }
    tab_button.into()
}

fn topbar_picker<'a, T>(
    options: &'a [T],
    selected: Option<T>,
    on_selected: impl Fn(T) -> Message + 'static,
    width: f32,
) -> Element<'a, Message>
where
    T: ToString + Clone + PartialEq + 'a,
{
    pick_list(options, selected, on_selected).width(width).into()
}

fn section_heading<'a>(title: &'static str, subtitle: &'static str) -> Element<'a, Message> {
    column![
        text(title).size(28),
        text(subtitle).size(15).color(Color::from_rgb8(95, 103, 120)),
    ]
    .spacing(8)
    .into()
}

fn card_style() -> iced::widget::container::Style {
    iced::widget::container::Style {
        background: Some(Background::Color(Color::WHITE)),
        border: Border {
            width: 1.0,
            radius: 24.0.into(),
            color: Color::from_rgb8(229, 231, 235),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba8(15, 23, 42, 0.06),
            offset: iced::Vector::new(0.0, 12.0),
            blur_radius: 32.0,
        },
        ..Default::default()
    }
}

fn format_near_amount(yocto_str: &str) -> String {
    if let Ok(yocto) = yocto_str.parse::<u128>() {
        let whole = yocto / 10u128.pow(24);
        let frac = yocto % 10u128.pow(24);
        if frac == 0 {
            format!("{whole} NEAR")
        } else {
            let frac_str = format!("{:024}", frac);
            let trimmed = frac_str.trim_end_matches('0');
            format!("{whole}.{trimmed} NEAR")
        }
    } else {
        format!("{yocto_str} yoctoNEAR")
    }
}

fn mask_mnemonic(mnemonic: &str) -> String {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if words.is_empty() {
        return "Mnemonic is empty".to_owned();
    }

    match words.last() {
        Some(last) => format!("... {last} ({} words)", words.len()),
        None => format!("{} word(s)", words.len()),
    }
}

async fn unlock_or_initialize_session(db: sled::Db, password: String) -> Result<VaultSession, String> {
    if password.is_empty() {
        return Err("session password is required".to_owned());
    }

    let salt = match db
        .get(VAULT_SALT_KEY)
        .map_err(|e| format!("failed to read vault salt: {e}"))?
    {
        Some(value) => value.to_vec(),
        None => {
            PasswordPolicy::default()
                .validate_password(&password)
                .await
                .map_err(|e| e.to_string())?;
            let salt = random_bytes(16)?;
            let verifier = PasswordPolicy::hash_password(&password)
                .await
                .map_err(|e| e.to_string())?;
            db.insert(VAULT_SALT_KEY, salt.clone())
                .map_err(|e| format!("failed to initialize vault salt: {e}"))?;
            db.insert(VAULT_VERIFIER_KEY, verifier.as_bytes())
                .map_err(|e| format!("failed to initialize vault verifier: {e}"))?;
            db.insert(ACCOUNTS_DB_KEY, b"[]".as_slice())
                .map_err(|e| format!("failed to initialize accounts store: {e}"))?;
            db.flush()
                .map_err(|e| format!("failed to flush vault initialization: {e}"))?;
            salt
        }
    };

    let stored_verifier = db
        .get(VAULT_VERIFIER_KEY)
        .map_err(|e| format!("failed to read vault verifier: {e}"))?
        .ok_or_else(|| "vault metadata is incomplete".to_owned())?;

    let stored_verifier = std::str::from_utf8(stored_verifier.as_ref())
        .map_err(|e| format!("stored vault verifier is not valid UTF-8: {e}"))?;
    PasswordPolicy::verify_password(&password, stored_verifier)
        .await
        .map_err(|e| e.to_string())?;

    let encryption_key_vec = derive_key(&password, &labeled_salt(&salt, b"encryption"))?;
    let encryption_key: [u8; KEY_LEN] = encryption_key_vec
        .try_into()
        .map_err(|_| "derived an invalid encryption key length".to_owned())?;
    let stored_accounts = load_stored_accounts(&db)?;
    let accounts = stored_accounts
        .into_iter()
        .map(|account| {
            let mnemonic = decrypt_secret(&encryption_key, &account.encrypted_mnemonic)?;
            Ok(UnlockedAccount {
                account_id: account.account_id,
                mnemonic,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(VaultSession {
        encryption_key,
        accounts,
    })
}

async fn change_vault_password(
    db: sled::Db,
    current_password: String,
    new_password: String,
    confirm_new_password: String,
) -> Result<(), String> {
    if current_password.is_empty() {
        return Err("current password is required".to_owned());
    }
    if new_password.is_empty() {
        return Err("new password is required".to_owned());
    }
    if new_password != confirm_new_password {
        return Err("new password confirmation does not match".to_owned());
    }

    let salt = db
        .get(VAULT_SALT_KEY)
        .map_err(|e| format!("failed to read vault salt: {e}"))?
        .ok_or_else(|| "vault metadata is incomplete".to_owned())?;
    let stored_verifier = db
        .get(VAULT_VERIFIER_KEY)
        .map_err(|e| format!("failed to read vault verifier: {e}"))?
        .ok_or_else(|| "vault metadata is incomplete".to_owned())?;
    let stored_verifier = std::str::from_utf8(stored_verifier.as_ref())
        .map_err(|e| format!("stored vault verifier is not valid UTF-8: {e}"))?;

    PasswordPolicy::verify_password(&current_password, stored_verifier)
        .await
        .map_err(|e| e.to_string())?;
    PasswordPolicy::default()
        .validate_password(&new_password)
        .await
        .map_err(|e| e.to_string())?;

    let current_key_vec = derive_key(&current_password, &labeled_salt(salt.as_ref(), b"encryption"))?;
    let current_key: [u8; KEY_LEN] = current_key_vec
        .try_into()
        .map_err(|_| "derived an invalid current encryption key length".to_owned())?;

    let decrypted_accounts = load_stored_accounts(&db)?
        .into_iter()
        .map(|account| {
            let mnemonic = decrypt_secret(&current_key, &account.encrypted_mnemonic)?;
            Ok((account.account_id, mnemonic))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let new_salt = random_bytes(16)?;
    let new_verifier = PasswordPolicy::hash_password(&new_password)
        .await
        .map_err(|e| e.to_string())?;
    let new_key_vec = derive_key(&new_password, &labeled_salt(&new_salt, b"encryption"))?;
    let new_key: [u8; KEY_LEN] = new_key_vec
        .try_into()
        .map_err(|_| "derived an invalid new encryption key length".to_owned())?;

    let migrated_accounts = decrypted_accounts
        .into_iter()
        .map(|(account_id, mnemonic)| {
            Ok(StoredAccount {
                account_id,
                encrypted_mnemonic: encrypt_secret(&new_key, &mnemonic)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let bytes = serde_json::to_vec_pretty(&migrated_accounts)
        .map_err(|e| format!("failed to encode migrated accounts: {e}"))?;
    db.insert(VAULT_SALT_KEY, new_salt)
        .map_err(|e| format!("failed to store new vault salt: {e}"))?;
    db.insert(VAULT_VERIFIER_KEY, new_verifier.as_bytes())
        .map_err(|e| format!("failed to store new vault verifier: {e}"))?;
    db.insert(ACCOUNTS_DB_KEY, bytes)
        .map_err(|e| format!("failed to store migrated accounts: {e}"))?;
    db.flush()
        .map_err(|e| format!("failed to flush password migration: {e}"))?;

    Ok(())
}

fn save_account(
    db: &sled::Db,
    session: &mut VaultSession,
    account_id_input: &str,
    mnemonic_input: &str,
) -> Result<String, String> {
    let account_id = account_id_input.trim();
    if account_id.is_empty() {
        return Err("account is required".to_owned());
    }
    account_id
        .parse::<AccountId>()
        .map_err(|e| format!("invalid NEAR account id: {e}"))?;

    let mnemonic = mnemonic_input.trim();
    if mnemonic.is_empty() {
        return Err("mnemonic is required".to_owned());
    }

    let candidate_public_key = derive_public_key_from_mnemonic(mnemonic)?;
    if session
        .accounts
        .iter()
        .any(|account| account.account_id == account_id && derive_public_key(account) == candidate_public_key)
    {
        return Err("that account and public key are already saved".to_owned());
    }

    let mut stored_accounts = load_stored_accounts(db)?;
    let encrypted_mnemonic = encrypt_secret(&session.encryption_key, mnemonic)?;
    stored_accounts.push(StoredAccount {
        account_id: account_id.to_owned(),
        encrypted_mnemonic,
    });

    let bytes = serde_json::to_vec_pretty(&stored_accounts).map_err(|e| format!("failed to encode accounts: {e}"))?;
    db.insert(ACCOUNTS_DB_KEY, bytes)
        .map_err(|e| format!("failed to store account: {e}"))?;
    db.flush().map_err(|e| format!("failed to flush accounts: {e}"))?;

    session.accounts.push(UnlockedAccount {
        account_id: account_id.to_owned(),
        mnemonic: mnemonic.to_owned(),
    });

    Ok(account_id.to_owned())
}

fn load_stored_accounts(db: &sled::Db) -> Result<Vec<StoredAccount>, String> {
    match db
        .get(ACCOUNTS_DB_KEY)
        .map_err(|e| format!("failed to read stored accounts: {e}"))?
    {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("failed to decode stored accounts: {e}")),
        None => Ok(vec![]),
    }
}

fn remove_account(
    db: &sled::Db,
    session: &mut VaultSession,
    account_id: &str,
    public_key: &str,
) -> Result<String, String> {
    let trimmed = account_id.trim();
    if trimmed.is_empty() {
        return Err("account is required".to_owned());
    }
    let trimmed_public_key = public_key.trim();
    if trimmed_public_key.is_empty() {
        return Err("public key is required".to_owned());
    }

    let mut stored_accounts = load_stored_accounts(db)?;
    let original_len = stored_accounts.len();
    stored_accounts.retain(|account| {
        if account.account_id != trimmed {
            return true;
        }

        match decrypt_secret(&session.encryption_key, &account.encrypted_mnemonic)
            .and_then(|mnemonic| derive_public_key_from_mnemonic(&mnemonic))
        {
            Ok(derived_public_key) => derived_public_key != trimmed_public_key,
            Err(_) => true,
        }
    });
    if stored_accounts.len() == original_len {
        return Err(format!(
            "account {trimmed} with public key {trimmed_public_key} was not found in the offline keychain"
        ));
    }

    let bytes = serde_json::to_vec_pretty(&stored_accounts).map_err(|e| format!("failed to encode accounts: {e}"))?;
    db.insert(ACCOUNTS_DB_KEY, bytes)
        .map_err(|e| format!("failed to store account removal: {e}"))?;
    db.flush()
        .map_err(|e| format!("failed to flush account removal: {e}"))?;

    session
        .accounts
        .retain(|account| !(account.account_id == trimmed && derive_public_key(account) == trimmed_public_key));

    Ok(trimmed.to_owned())
}

fn labeled_salt(base_salt: &[u8], label: &[u8]) -> Vec<u8> {
    let mut bytes = base_salt.to_vec();
    bytes.extend_from_slice(label);
    bytes
}

fn argon2_params() -> Result<Params, String> {
    Params::new(19_456, 2, 1, Some(KEY_LEN)).map_err(|e| format!("failed to configure argon2 params: {e}"))
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = [0u8; KEY_LEN];

    let params = argon2_params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| format!("failed to derive encryption key: {e}"))?;

    Ok(output.to_vec())
}

fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

fn encrypt_secret(key_bytes: &[u8; KEY_LEN], plaintext: &str) -> Result<EncryptedSecret, String> {
    let cipher = Aes256Gcm::new_from_slice(key_bytes).map_err(|_| "failed to initialize encryption key".to_owned())?;
    let nonce_bytes = random_bytes(NONCE_LEN)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| "failed to encrypt mnemonic".to_owned())?;

    Ok(EncryptedSecret {
        nonce_base64: STANDARD.encode(nonce_bytes),
        ciphertext_base64: STANDARD.encode(ciphertext),
    })
}

fn decrypt_secret(key_bytes: &[u8; KEY_LEN], encrypted: &EncryptedSecret) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key_bytes).map_err(|_| "failed to initialize decryption key".to_owned())?;
    let nonce_bytes = STANDARD
        .decode(&encrypted.nonce_base64)
        .map_err(|e| format!("failed to decode mnemonic nonce: {e}"))?;
    let ciphertext = STANDARD
        .decode(&encrypted.ciphertext_base64)
        .map_err(|e| format!("failed to decode mnemonic ciphertext: {e}"))?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err("stored mnemonic nonce has an invalid length".to_owned());
    }

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "failed to decrypt mnemonic; password may be incorrect or data is corrupted".to_owned())?;

    String::from_utf8(plaintext).map_err(|e| format!("decrypted mnemonic is not valid UTF-8: {e}"))
}

async fn load_request(path: String) -> Result<LoadedRequest, String> {
    if path.is_empty() {
        return Err("request file path is required".to_owned());
    }

    let content = fs::read_to_string(&path).map_err(|e| format!("failed to read request file: {e}"))?;
    let request = request_from_json(&content).map_err(|e| e.to_string())?;
    let verified = verify_request(&request).map_err(|e| e.to_string())?;
    Ok(LoadedRequest { request, verified })
}

async fn export_response(response: SignedTransactionResponse, output: PathBuf) -> Result<PathBuf, String> {
    let json = response_to_pretty_json(&response).map_err(|e| e.to_string())?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create output directory: {e}"))?;
    }
    fs::write(&output, json).map_err(|e| format!("failed to write response file: {e}"))?;
    Ok(output)
}

fn reset_vault(db: &sled::Db) -> Result<(), String> {
    db.clear().map_err(|e| format!("failed to clear local vault: {e}"))?;
    db.flush().map_err(|e| format!("failed to flush cleared vault: {e}"))?;
    Ok(())
}
