use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use airgap_core::{
    PasswordPolicy, SignedTransactionResponse, UnsignedTransactionRequest, VerifiedTransferRequest, request_from_json,
    response_to_pretty_json, sign_transfer_request, verify_transfer_request,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bip39::{Language, Mnemonic};
use bs58::encode as bs58_encode;
use ed25519_dalek::SigningKey;
use iced::{
    Alignment, Border, Color, Element, Length, Task, clipboard,
    widget::{button, column, container, pane_grid, pick_list, row, scrollable, text, text_input},
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
const SIDEBAR_RATIO: f32 = 0.24;
const SAVED_ACCOUNT_COLUMN_WIDTH: f32 = 180.0;
const SAVED_MNEMONIC_COLUMN_WIDTH: f32 = 170.0;
const DEFAULT_SEED_PHRASE_HD_PATH: &str = "m/44'/397'/0'";

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
    output_dir().join("signed-response.json").display().to_string()
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
    SplitResized(pane_grid::ResizeEvent),
    AccountIdChanged(String),
    MnemonicChanged(String),
    SaveAccountPressed,
    MnemonicLanguageSelected(MnemonicLanguage),
    GenerateMnemonicPressed,
    CopyGeneratedMnemonicPressed(String),
    LoadRequestPressed,
    RequestFileChanged(String),
    RequestLoaded(Result<LoadedRequest, String>),
    ConfirmAndSignPressed,
    Signed(Result<SignedTransactionResponse, String>),
    OutputChanged(String),
    ExportPressed,
    Exported(Result<PathBuf, String>),
    ResetPressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Sign,
    Accounts,
    Mnemonic,
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
    layout: pane_grid::State<LayoutPane>,
    session: VaultSession,
    account_id_input: String,
    mnemonic_input: String,
    mnemonic_language: MnemonicLanguage,
    generated_mnemonic: String,
    sign_state: SignState,
    request_file_path: String,
    output: String,
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
    Exported(PathBuf),
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
    verified: VerifiedTransferRequest,
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

#[derive(Debug, Clone, Copy)]
enum LayoutPane {
    Sidebar,
    Main,
}

struct OfflineApp {
    db: sled::Db,
    screen: AppScreen,
    status: Status,
}

impl Default for OfflineApp {
    fn default() -> Self {
        let db = sled::open(db_path()).expect("failed to open key database");

        Self {
            db,
            screen: AppScreen::Locked(LockedState {
                password: String::new(),
                reset_confirmation_required: false,
            }),
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
                    self.screen = AppScreen::Locked(LockedState {
                        password: String::new(),
                        reset_confirmation_required: false,
                    });
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
                        layout: build_split_layout(),
                        sign_state: SignState::Idle,
                        request_file_path: String::new(),
                        output: default_output_path(),
                        account_id_input: String::new(),
                        mnemonic_input: String::new(),
                        mnemonic_language: MnemonicLanguage::ChineseSimplified,
                        generated_mnemonic: String::new(),
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
            Message::SplitResized(event) => {
                if let AppScreen::Unlocked(unlocked) = &mut self.screen {
                    unlocked.layout.resize(event.split, event.ratio);
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
            Message::CopyGeneratedMnemonicPressed(mnemonic) => {
                return clipboard::write(mnemonic);
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
                    async move { sign_transfer_request(&request, &secret_key).map_err(|e| e.to_string()) },
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
                            unlocked.sign_state = SignState::Exported(path);
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

    let content =
        column![
        text("🔐 Airgap Offline").size(34),
        text(
            "Enter the one-time password for this session. Stored mnemonics will be decrypted into memory after unlock."
        )
        .size(16),
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
        container(
            row![
                reset_controls,
                button(container(text("Unlock").size(14)).width(Length::Fill).center_x(Length::Fill))
                    .padding([10, 18])
                    .width(Length::Fixed(150.0))
                    .on_press(Message::UnlockPressed),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill),
        status_view(status),
    ]
        .spacing(24)
        .padding(32)
        .max_width(640)
        .align_x(Alignment::Center);

    container(container(content).center_x(Length::Fill).center_y(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn unlocked_view<'a>(unlocked: &'a UnlockedState, status: &'a Status) -> Element<'a, Message> {
    pane_grid(&unlocked.layout, |_, pane, _| match pane {
        LayoutPane::Sidebar => pane_grid::Content::new(sidebar_view(unlocked)),
        LayoutPane::Main => pane_grid::Content::new(main_view(unlocked, status)),
    })
    .width(Length::Fill)
    .height(Length::Fill)
    .spacing(1)
    .on_resize(8, Message::SplitResized)
    .into()
}

fn sidebar_view<'a>(unlocked: &'a UnlockedState) -> Element<'a, Message> {
    container(
        column![
            text("🔐 Airgap Offline").size(24),
            text("Offline vault").size(14),
            tab_button("Sign", Tab::Sign, unlocked.active_tab),
            tab_button("Keychain", Tab::Accounts, unlocked.active_tab),
            tab_button("Mnemonic", Tab::Mnemonic, unlocked.active_tab),
        ]
        .spacing(16)
        .padding(20)
        .align_x(Alignment::Start),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn main_view<'a>(unlocked: &'a UnlockedState, status: &'a Status) -> Element<'a, Message> {
    let body = match unlocked.active_tab {
        Tab::Sign => signing_tab(unlocked),
        Tab::Accounts => accounts_tab(unlocked),
        Tab::Mnemonic => mnemonic_tab(unlocked),
    };

    scrollable(
        container(
            column![body, status_view(status)]
                .spacing(24)
                .padding(28)
                .width(Length::Fill),
        )
        .width(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn tab_button<'a>(label: &'a str, tab: Tab, active_tab: Tab) -> Element<'a, Message> {
    let mut button_view = button(text(label).size(15)).padding([10, 18]).width(Length::Fill);
    if tab != active_tab {
        button_view = button_view.on_press(Message::TabSelected(tab));
    }
    button_view.into()
}

fn accounts_tab<'a>(unlocked: &'a UnlockedState) -> Element<'a, Message> {
    let accounts: Element<'a, Message> = if unlocked.session.accounts.is_empty() {
        column![text("No accounts saved yet. Add an account and encrypted mnemonic below.").size(14)].into()
    } else {
        saved_accounts_table(&unlocked.session.accounts)
    };

    column![
        text("Keychain").size(22),
        text(
            "Each mnemonic is encrypted in sled and only decrypted into memory after the session password is entered."
        )
        .size(14),
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
    .width(Length::Fill)
    .into()
}

fn mnemonic_tab<'a>(unlocked: &'a UnlockedState) -> Element<'a, Message> {
    let generated_view: Element<'a, Message> = if unlocked.generated_mnemonic.is_empty() {
        text("No mnemonic generated yet.").size(14).into()
    } else {
        column![
            text("Generated Mnemonic").size(18),
            row![
                container(text(unlocked.generated_mnemonic.as_str()).size(16))
                    .padding(16)
                    .width(Length::Fill),
                button(text("Copy").size(14))
                    .padding([10, 16])
                    .on_press(Message::CopyGeneratedMnemonicPressed(
                        unlocked.generated_mnemonic.clone()
                    )),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            text(mnemonic_safety_hint()).size(13),
        ]
        .spacing(12)
        .into()
    };

    column![
        text("Mnemonic Generator").size(22),
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
    .width(Length::Fill)
    .into()
}

fn saved_accounts_table(accounts: &[UnlockedAccount]) -> Element<'_, Message> {
    let header = row![
        container(text("Account").size(14)).width(SAVED_ACCOUNT_COLUMN_WIDTH),
        container(text("Mnemonic").size(14)).width(SAVED_MNEMONIC_COLUMN_WIDTH),
        container(text("Public Key").size(14)).width(Length::Fill),
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
    column![
        row![
            container(text(&account.account_id).size(15)).width(SAVED_ACCOUNT_COLUMN_WIDTH),
            container(text(mask_mnemonic(&account.mnemonic)).size(13)).width(SAVED_MNEMONIC_COLUMN_WIDTH),
            container(text(derive_public_key(account)).size(13)).width(Length::Fill),
        ]
        .spacing(16)
        .align_y(Alignment::Center),
        table_divider(),
    ]
    .spacing(10)
    .into()
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
    column![
        mnemonic_status_view(&unlocked.session),
        signing_keychain_view(&unlocked.session, &unlocked.sign_state),
        signing_section(&unlocked.sign_state, &unlocked.request_file_path, &unlocked.output),
        actions_row(&unlocked.sign_state),
    ]
    .spacing(24)
    .width(Length::Fill)
    .into()
}

fn mnemonic_status_view(session: &VaultSession) -> Element<'_, Message> {
    let summary = if session.accounts.is_empty() {
        "0 unlocked accounts in memory".to_owned()
    } else {
        format!("{} unlocked account(s) in memory", session.accounts.len())
    };

    column![
        text("Vault Session").size(18),
        text(summary).size(14),
        text("This prepares the in-memory account list for a future signer account dropdown.").size(13),
    ]
    .spacing(6)
    .into()
}

fn signing_keychain_view<'a>(session: &'a VaultSession, sign_state: &'a SignState) -> Element<'a, Message> {
    let helper = match sign_state {
        SignState::RequestLoaded(loaded) => {
            let signer = &loaded.verified.signer_id;
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
        SignState::Signed(response) => {
            sections.push(signed_details_view(response));
        }
        SignState::Exported(path) => {
            sections.push(exported_view(path));
        }
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

    column(sections).spacing(24).into()
}

fn transaction_details_view(request: &VerifiedTransferRequest) -> Element<'_, Message> {
    let details = column![
        detail_row("Network".into(), request.network.to_string()),
        detail_row("Signer".into(), request.signer_id.clone()),
        detail_row("Signer Public Key".into(), request.signer_public_key.clone()),
        detail_row("Receiver".into(), request.receiver_id.clone()),
        detail_row("Nonce".into(), request.nonce.to_string()),
        detail_row("Recent Block Hash".into(), request.block_hash.clone()),
        detail_row("Deposit".into(), format_near_amount(&request.deposit_yocto_near)),
        detail_row("Request ID".into(), request.request_id.clone()),
    ]
    .spacing(8);

    container(
        column![text("Transaction Details").size(16), details]
            .spacing(12)
            .width(Length::Fill),
    )
    .padding(16)
    .width(Length::Fill)
    .style(|_| iced::widget::container::Style {
        border: Border {
            width: 1.0,
            radius: 10.0.into(),
            color: Color::from_rgb8(34, 197, 94),
        },
        background: Some(Color::from_rgb8(240, 253, 244).into()),
        text_color: None,
        shadow: iced::Shadow::default(),
        snap: false,
    })
    .into()
}

fn signed_details_view(response: &SignedTransactionResponse) -> Element<'_, Message> {
    column![
        text("Transaction Signed").size(16),
        column![
            detail_row("Request ID".into(), response.request_id.clone()),
            detail_row("Public Key".into(), response.public_key.clone()),
            detail_row("Signature".into(), response.signature.clone()),
        ]
        .spacing(8),
    ]
    .spacing(12)
    .into()
}

fn exported_view(path: &PathBuf) -> Element<'_, Message> {
    column![
        text("Response Exported").size(16),
        column![
            detail_row("Path".into(), path.display().to_string()),
            text("Transfer this file to the online machine for broadcasting.").size(13),
        ]
        .spacing(8),
    ]
    .spacing(12)
    .into()
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
                button(text("Export Response").size(16))
                    .padding([12, 18])
                    .on_press(Message::ExportPressed),
            );
        }
        SignState::Exported(_) | SignState::Idle => {
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
    let verified = verify_transfer_request(request).map_err(|e| e.to_string())?;
    let account = accounts
        .iter()
        .find(|account| account.account_id == verified.signer_id)
        .ok_or_else(|| format!("no Keychain account matches signer {}", verified.signer_id))?;

    let secret_key = derive_secret_key(account);
    let derived_public_key = secret_key.public_key().to_string();

    if derived_public_key != verified.signer_public_key {
        return Err(format!(
            "keychain mnemonic for {} derives public key {}, but the transaction expects {}",
            account.account_id, derived_public_key, verified.signer_public_key
        ));
    }

    Ok(secret_key)
}

fn derive_secret_key(account: &UnlockedAccount) -> SecretKey {
    derive_secret_key_from_mnemonic(account.mnemonic.trim())
        .expect("stored mnemonic should derive a valid NEAR secret key")
}

fn derive_public_key(account: &UnlockedAccount) -> String {
    derive_secret_key(account).public_key().to_string()
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

    match (words.first(), words.last()) {
        (Some(first), Some(last)) if words.len() > 2 => {
            format!("{first} ... {last} ({} words)", words.len())
        }
        _ => format!("{} word(s)", words.len()),
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

    if session.accounts.iter().any(|account| account.account_id == account_id) {
        return Err("that account is already saved".to_owned());
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
    let verified = verify_transfer_request(&request).map_err(|e| e.to_string())?;
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

fn build_split_layout() -> pane_grid::State<LayoutPane> {
    let (mut layout, sidebar) = pane_grid::State::new(LayoutPane::Sidebar);
    if let Some((main, split)) = layout.split(pane_grid::Axis::Vertical, sidebar, LayoutPane::Main) {
        let _ = main;
        layout.resize(split, SIDEBAR_RATIO);
    }
    layout
}

fn reset_vault(db: &sled::Db) -> Result<(), String> {
    db.clear().map_err(|e| format!("failed to clear local vault: {e}"))?;
    db.flush().map_err(|e| format!("failed to flush cleared vault: {e}"))?;
    Ok(())
}
