use airgap_core::{
    AddKeyDraft, DeleteKeyDraft, SignedTransactionResponse, TransferDraft,
    cfg::{
        language::SupportLanguage,
        network::Network,
        rpc::{JsonRpc, ProviderKind},
    },
    request_to_pretty_json, response_from_json,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use borsh::from_slice;
use iced::{
    Alignment, Background, Border, Color, Element, Length, Task, alignment, clipboard,
    widget::{button, column, container, pick_list, row, scrollable, svg, text, text_input},
};
use near_primitives::transaction::{Action, SignedTransaction, Transaction};
use near_primitives::types::Balance;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::PathBuf};
use tracing_subscriber::EnvFilter;
const NETWORK_COLUMN_WIDTH: f32 = 120.0;
const PERMISSION_COLUMN_WIDTH: f32 = 140.0;
const ACCOUNT_COLUMN_WIDTH: f32 = 220.0;
const ACTION_COLUMN_WIDTH: f32 = 88.0;
const COPY_ICON_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../asset/mingcute-copy.svg");
const DELETE_ICON_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../asset/mingcute-delete.svg");
const SEND_ICON_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../asset/mingcute-send.svg");
const SAVED_ACCOUNT_KEYS_DB_KEY: &[u8] = b"saved_account_keys";
const PROVIDERS: [ProviderKind; 2] = [ProviderKind::Lava, ProviderKind::Fastnear];
const SUPPORTED_LANGUAGES: [SupportLanguage; 2] = [SupportLanguage::English, SupportLanguage::Chinese];

pub(crate) mod external;
pub(crate) mod model;

fn main() -> iced::Result {
    let filter = EnvFilter::new("info")
        .add_directive("iced_wgpu=off".parse().expect("invalid iced_wgpu directive"))
        .add_directive("iced_winit=off".parse().expect("invalid iced_winit directive"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_thread_names(true)
        .with_timer(tracing_subscriber::fmt::time::OffsetTime::local_rfc_3339().expect("can't get local offset"))
        .init();

    iced::application(OnlineApp::default, OnlineApp::update, OnlineApp::view)
        .title("🔥 Airgap Online")
        .window_size((1080.0, 720.0))
        .centered()
        .run()
}

fn db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".airgap").join("airgap-online").join("db")
}

fn output_dir() -> PathBuf {
    db_path()
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(db_path)
        .join("out")
}

fn default_output_path() -> String {
    output_dir().join("transaction-unsigned.json").display().to_string()
}

#[derive(Debug, Clone)]
enum Message {
    TabSelected(Tab),
    NetworkChanged(Network),
    ProviderChanged(ProviderKind),
    LanguageChanged(SupportLanguage),
    SignerIdChanged(String),
    SignerKnownAccountSelected(String),
    SignerPublicKeyChanged(String),
    SignerKnownPublicKeySelected(String),
    DeleteKeyPublicKeyChanged(String),
    DeleteKeyKnownPublicKeySelected(String),
    AddKeyPublicKeyChanged(String),
    ReceiverIdChanged(String),
    ReceiverKnownAccountSelected(String),
    NonceChanged(String),
    BlockHashChanged(String),
    DepositChanged(String),
    OutputChanged(String),
    FetchChainStatePressed,
    ChainStateFetched(Result<ChainState, String>),
    AccountLookupChanged(String),
    FetchAccountKeysPressed,
    ViewAccountLookupChanged(String),
    FetchViewAccountPressed,
    RefreshAccountKeysPressed,
    CleanupAccountKeysPressed,
    DeleteSavedAccountKeyPressed {
        account_id: String,
        network: Network,
        public_key: String,
    },
    AccountKeysFetched(Result<LoadedAccountKeys, String>),
    ViewAccountFetched(Result<ViewAccountData, String>),
    AccountDirectoryRefreshed(Result<LoadedAccountDirectory, String>),
    CopyPressed(String),
    GeneratePressed,
    SignedResponsePathChanged(String),
    LoadSignedResponsePressed,
    SignedResponseLoaded(Result<LoadedSignedResponse, String>),
    BroadcastSignedTransactionPressed,
    BroadcastFinished(Result<BroadcastResult, String>),
}

#[derive(Debug)]
struct OnlineApp {
    db: sled::Db,
    active_tab: Tab,
    network: Network,
    provider: ProviderKind,
    language: SupportLanguage,
    signer_id: String,
    signer_public_key: String,
    delete_key_public_key: String,
    add_key_public_key: String,
    receiver_id: String,
    nonce: String,
    block_hash: String,
    deposit_near: String,
    output: String,
    status: Status,
    last_generated: Option<RequestSnapshot>,
    account_lookup: String,
    view_account_lookup: String,
    account_directory: BTreeMap<String, Vec<AccountAccessKeyRow>>,
    account_status: AccountStatus,
    view_account_state: ViewAccountState,
    signed_response_path: String,
    broadcast_state: BroadcastState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    ViewAccount,
    ViewKnownAccount,
    Sign,
    SignDelKeys,
    SignAddKey,
    Broadcast,
}

impl Default for OnlineApp {
    fn default() -> Self {
        let db = sled::open(db_path()).expect("failed to open online account database");
        let account_directory = load_saved_account_keys(&db).unwrap_or_default();

        Self {
            db,
            active_tab: Tab::Sign,
            network: Network::Mainnet,
            provider: ProviderKind::Lava,
            language: SupportLanguage::English,
            signer_id: String::new(),
            signer_public_key: String::new(),
            delete_key_public_key: String::new(),
            add_key_public_key: String::new(),
            receiver_id: String::new(),
            nonce: String::new(),
            block_hash: String::new(),
            deposit_near: String::new(),
            output: default_output_path(),
            status: Status::Idle,
            last_generated: None,
            account_lookup: String::new(),
            view_account_lookup: String::new(),
            account_directory,
            account_status: AccountStatus::Idle,
            view_account_state: ViewAccountState::Idle,
            signed_response_path: default_signed_response_path(),
            broadcast_state: BroadcastState::Idle,
        }
    }
}

impl OnlineApp {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::TabSelected(tab) => {
                self.active_tab = tab;
            }
            Message::NetworkChanged(network) => {
                self.network = network;
                self.signer_public_key =
                    default_public_key_for_network(&self.account_directory, self.signer_id.trim(), network);
                self.delete_key_public_key =
                    default_public_key_for_network(&self.account_directory, self.signer_id.trim(), network);
                self.mark_dirty();
            }
            Message::ProviderChanged(provider) => {
                self.provider = provider;
            }
            Message::LanguageChanged(language) => {
                self.language = language;
            }
            Message::SignerIdChanged(value) => {
                self.signer_id = value;
                self.mark_dirty();
            }
            Message::SignerKnownAccountSelected(account_id) => {
                self.signer_id = account_id.clone();
                self.signer_public_key =
                    default_public_key_for_network(&self.account_directory, &account_id, self.network);
                self.delete_key_public_key =
                    default_public_key_for_network(&self.account_directory, &account_id, self.network);
                self.mark_dirty();
            }
            Message::SignerPublicKeyChanged(value) => {
                self.signer_public_key = value;
                self.mark_dirty();
            }
            Message::SignerKnownPublicKeySelected(public_key) => {
                self.signer_public_key = public_key;
                self.mark_dirty();
            }
            Message::DeleteKeyPublicKeyChanged(value) => {
                self.delete_key_public_key = value;
                self.mark_dirty();
            }
            Message::DeleteKeyKnownPublicKeySelected(public_key) => {
                self.delete_key_public_key = public_key;
                self.mark_dirty();
            }
            Message::AddKeyPublicKeyChanged(value) => {
                self.add_key_public_key = value;
                self.mark_dirty();
            }
            Message::ReceiverIdChanged(value) => {
                self.receiver_id = value;
                self.mark_dirty();
            }
            Message::ReceiverKnownAccountSelected(account_id) => {
                self.receiver_id = account_id;
                self.mark_dirty();
            }
            Message::NonceChanged(value) => {
                self.nonce = value;
                self.mark_dirty();
            }
            Message::BlockHashChanged(value) => {
                self.block_hash = value;
                self.mark_dirty();
            }
            Message::DepositChanged(value) => {
                self.deposit_near = value;
                self.mark_dirty();
            }
            Message::OutputChanged(value) => {
                self.output = value;
                self.mark_dirty();
            }
            Message::FetchChainStatePressed => {
                self.status = Status::Fetching;
                return Task::perform(
                    fetch_chain_state(
                        self.network,
                        self.provider,
                        self.signer_id.trim().to_owned(),
                        self.signer_public_key.trim().to_owned(),
                    ),
                    Message::ChainStateFetched,
                );
            }
            Message::ChainStateFetched(result) => match result {
                Ok(chain_state) => {
                    self.nonce = chain_state.next_nonce.to_string();
                    self.block_hash = chain_state.block_hash.clone();
                    self.status = Status::Fetched(chain_state);
                    self.mark_dirty();
                }
                Err(error) => self.status = Status::Error(error),
            },
            Message::AccountLookupChanged(value) => {
                self.account_lookup = value;
            }
            Message::FetchAccountKeysPressed => {
                let account_id = self.account_lookup.trim().to_owned();
                let network = self.network;
                let provider = self.provider;
                self.account_status = AccountStatus::Fetching;
                return Task::perform(
                    fetch_account_keys(network, provider, account_id),
                    Message::AccountKeysFetched,
                );
            }
            Message::ViewAccountLookupChanged(value) => {
                self.view_account_lookup = value;
            }
            Message::FetchViewAccountPressed => {
                let account_id = self.view_account_lookup.trim().to_owned();
                let network = self.network;
                let provider = self.provider;
                self.view_account_state = ViewAccountState::Fetching;
                return Task::perform(
                    fetch_view_account(network, provider, account_id),
                    Message::ViewAccountFetched,
                );
            }
            Message::RefreshAccountKeysPressed => {
                let network = self.network;
                let provider = self.provider;
                let account_ids = self
                    .account_directory
                    .iter()
                    .filter(|(_, rows)| rows.iter().any(|entry| entry.network == network))
                    .map(|(account_id, _)| account_id.clone())
                    .collect();
                self.account_status = AccountStatus::Fetching;
                return Task::perform(
                    fetch_all_account_keys(network, provider, account_ids),
                    Message::AccountDirectoryRefreshed,
                );
            }
            Message::CleanupAccountKeysPressed => match clear_saved_account_keys(&self.db, &mut self.account_directory)
            {
                Ok(()) => {
                    self.account_status = AccountStatus::Idle;
                }
                Err(error) => self.account_status = AccountStatus::Error(error),
            },
            Message::DeleteSavedAccountKeyPressed {
                account_id,
                network,
                public_key,
            } => {
                match delete_saved_account_key(&self.db, &mut self.account_directory, &account_id, network, &public_key)
                {
                    Ok(()) => {
                        self.account_status = AccountStatus::Idle;
                    }
                    Err(error) => self.account_status = AccountStatus::Error(error),
                }
            }
            Message::AccountKeysFetched(result) => match result {
                Ok(loaded) => {
                    let key_count = loaded.rows.len();
                    self.account_lookup = loaded.account_id.clone();
                    let account_id = loaded.account_id.clone();
                    match save_account_keys(&self.db, &mut self.account_directory, loaded) {
                        Ok(()) => {
                            self.account_status = AccountStatus::Loaded { account_id, key_count };
                        }
                        Err(error) => self.account_status = AccountStatus::Error(error),
                    }
                }
                Err(error) => self.account_status = AccountStatus::Error(error),
            },
            Message::ViewAccountFetched(result) => match result {
                Ok(loaded) => {
                    self.view_account_lookup = loaded.account_id.clone();
                    self.view_account_state = ViewAccountState::Loaded(loaded);
                }
                Err(error) => self.view_account_state = ViewAccountState::Error(error),
            },
            Message::AccountDirectoryRefreshed(result) => match result {
                Ok(loaded) => {
                    let key_count = loaded.key_count;
                    match replace_saved_account_keys(&self.db, &mut self.account_directory, loaded) {
                        Ok(()) => {
                            self.account_status = AccountStatus::Refreshed {
                                account_count: self.account_directory.len(),
                                key_count,
                            };
                        }
                        Err(error) => self.account_status = AccountStatus::Error(error),
                    }
                }
                Err(error) => self.account_status = AccountStatus::Error(error),
            },
            Message::CopyPressed(content) => {
                return clipboard::write(content);
            }
            Message::GeneratePressed => {
                if self.can_generate() {
                    self.status = match self.generate_request() {
                        Ok(result) => {
                            self.last_generated = Some(result.snapshot.clone());
                            Status::Success(result)
                        }
                        Err(error) => Status::Error(error),
                    };
                }
            }
            Message::SignedResponsePathChanged(value) => {
                self.signed_response_path = value;
                if matches!(
                    self.broadcast_state,
                    BroadcastState::Loaded(_) | BroadcastState::Broadcasted(_)
                ) {
                    self.broadcast_state = BroadcastState::Idle;
                }
            }
            Message::LoadSignedResponsePressed => {
                let path = self.signed_response_path.trim().to_owned();
                self.broadcast_state = BroadcastState::Loading;
                return Task::perform(load_signed_response(path), Message::SignedResponseLoaded);
            }
            Message::SignedResponseLoaded(result) => match result {
                Ok(loaded) => self.broadcast_state = BroadcastState::Loaded(loaded),
                Err(error) => self.broadcast_state = BroadcastState::Error(error),
            },
            Message::BroadcastSignedTransactionPressed => {
                let loaded = match &self.broadcast_state {
                    BroadcastState::Loaded(loaded) => loaded.clone(),
                    _ => return Task::none(),
                };
                self.broadcast_state = BroadcastState::Broadcasting;
                return Task::perform(
                    broadcast_signed_transaction(self.network, self.provider, loaded),
                    Message::BroadcastFinished,
                );
            }
            Message::BroadcastFinished(result) => match result {
                Ok(result) => self.broadcast_state = BroadcastState::Broadcasted(result),
                Err(error) => self.broadcast_state = BroadcastState::Error(error),
            },
        }

        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let shell = column![top_bar(self), online_main_view(self)]
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

    fn generate_request(&self) -> Result<GeneratedRequest, String> {
        let nonce = parse_u64("nonce", &self.nonce)?;
        let output = parse_output_path(&self.output)?;
        let request = match self.active_tab {
            Tab::Sign => {
                let deposit = parse_near_amount(&self.deposit_near)?;
                TransferDraft {
                    network: self.network,
                    signer_id: self.signer_id.trim().to_owned(),
                    signer_public_key: self.signer_public_key.trim().to_owned(),
                    receiver_id: self.receiver_id.trim().to_owned(),
                    nonce,
                    block_hash: self.block_hash.trim().to_owned(),
                    deposit_yocto_near: deposit,
                }
                .into_request()
            }
            Tab::SignDelKeys => DeleteKeyDraft {
                network: self.network,
                signer_id: self.signer_id.trim().to_owned(),
                signer_public_key: self.signer_public_key.trim().to_owned(),
                receiver_id: self.signer_id.trim().to_owned(),
                nonce,
                block_hash: self.block_hash.trim().to_owned(),
                delete_public_key: self.delete_key_public_key.trim().to_owned(),
            }
            .into_request(),
            Tab::SignAddKey => AddKeyDraft {
                network: self.network,
                signer_id: self.signer_id.trim().to_owned(),
                signer_public_key: self.signer_public_key.trim().to_owned(),
                receiver_id: self.signer_id.trim().to_owned(),
                nonce,
                block_hash: self.block_hash.trim().to_owned(),
                add_public_key: self.add_key_public_key.trim().to_owned(),
            }
            .into_request(),
            Tab::Broadcast | Tab::ViewKnownAccount | Tab::ViewAccount => {
                return Err("request generation is only available from a Gen-* tab".to_owned());
            }
        }
        .map_err(|error| error.to_string())?;

        let json = request_to_pretty_json(&request).map_err(|error| error.to_string())?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|error| format!("failed to create output directory: {error}"))?;
        }
        fs::write(&output, json).map_err(|error| format!("failed to write output file: {error}"))?;
        let output = output.canonicalize().unwrap_or(output);

        let snapshot = self.request_snapshot();
        Ok(GeneratedRequest {
            id: request.id,
            output,
            snapshot,
        })
    }

    fn can_generate(&self) -> bool {
        self.last_generated.as_ref() != Some(&self.request_snapshot())
    }

    fn mark_dirty(&mut self) {
        if self.can_generate() && matches!(self.status, Status::Success(_)) {
            self.status = Status::Idle;
        }
    }

    fn request_snapshot(&self) -> RequestSnapshot {
        RequestSnapshot {
            active_tab: self.active_tab,
            network: self.network,
            signer_id: self.signer_id.trim().to_owned(),
            signer_public_key: self.signer_public_key.trim().to_owned(),
            delete_key_public_key: self.delete_key_public_key.trim().to_owned(),
            add_key_public_key: self.add_key_public_key.trim().to_owned(),
            receiver_id: self.receiver_id.trim().to_owned(),
            nonce: self.nonce.trim().to_owned(),
            block_hash: self.block_hash.trim().to_owned(),
            deposit_near: self.deposit_near.trim().to_owned(),
            output: self.output.trim().to_owned(),
        }
    }
}

fn top_bar(app: &OnlineApp) -> Element<'_, Message> {
    let spacer = container(text("")).width(Length::Fill);
    let title = row![
        container(
            container(text("🔥").size(20))
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
            text("Airgap Online").size(24),
            text("Hot machine").size(13).color(Color::from_rgb8(107, 114, 128))
        ]
        .spacing(2)
    ]
    .spacing(14)
    .align_y(Alignment::Center);

    let provider = topbar_picker(&PROVIDERS, Some(app.provider), Message::ProviderChanged, 160.0);
    let language = topbar_picker(
        &SUPPORTED_LANGUAGES,
        Some(app.language),
        Message::LanguageChanged,
        160.0,
    );

    container(
        row![title, spacer, provider, language]
            .spacing(16)
            .align_y(Alignment::Center),
    )
    .padding([20, 28])
    .width(Length::Fill)
    .style(|_| iced::widget::container::Style {
        background: Some(Background::Color(Color::WHITE)),
        border: Border {
            width: 0.0,
            radius: 0.0.into(),
            color: Color::TRANSPARENT,
        },
        ..Default::default()
    })
    .into()
}

fn online_main_view(app: &OnlineApp) -> Element<'_, Message> {
    let hero = hero_section(app.active_tab);
    let tabs = tab_strip(app.active_tab);
    let content = match app.active_tab {
        Tab::Sign => online_sign_view(app),
        Tab::SignDelKeys => online_del_keys_view(app),
        Tab::SignAddKey => online_add_key_view(app),
        Tab::Broadcast => online_broadcast_view(app),
        Tab::ViewKnownAccount => online_accounts_view(app),
        Tab::ViewAccount => online_view_account_view(app),
    };

    scrollable(
        container(
            column![hero, tabs, content]
                .spacing(24)
                .width(Length::Fill)
                .max_width(1120),
        )
        .padding([28, 32])
        .center_x(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn online_broadcast_view(app: &OnlineApp) -> Element<'_, Message> {
    let network = column![
        text("Network").size(14),
        pick_list(
            [Network::Testnet, Network::Mainnet],
            Some(app.network),
            Message::NetworkChanged
        )
        .width(Length::Fill),
    ]
    .spacing(8);

    let response_input = column![
        text("Signed response file").size(14),
        row![
            text_input("Signed response file", &app.signed_response_path)
                .on_input(Message::SignedResponsePathChanged)
                .padding(12)
                .size(16)
                .width(Length::Fill),
            button(text("Load").size(16))
                .padding([12, 18])
                .on_press(Message::LoadSignedResponsePressed),
        ]
        .spacing(12)
        .align_y(Alignment::Center),
    ]
    .spacing(8);

    let mut actions = row![].spacing(12).align_y(Alignment::Center);
    if matches!(app.broadcast_state, BroadcastState::Loaded(_)) {
        actions = actions.push(
            button(
                svg(svg::Handle::from_path(SEND_ICON_PATH))
                    .width(Length::Fixed(16.0))
                    .height(Length::Fixed(16.0)),
            )
            .padding([12, 18])
            .style(|_, status| {
                let background = match status {
                    button::Status::Hovered => Some(Background::Color(Color::from_rgba8(99, 102, 241, 0.08))),
                    button::Status::Pressed => Some(Background::Color(Color::from_rgba8(99, 102, 241, 0.14))),
                    _ => None,
                };

                iced::widget::button::Style {
                    background,
                    border: Border {
                        width: 1.0,
                        radius: 10.0.into(),
                        color: Color::from_rgb8(99, 102, 241),
                    },
                    text_color: Color::from_rgb8(99, 102, 241),
                    shadow: iced::Shadow::default(),
                    snap: false,
                }
            })
            .on_press(Message::BroadcastSignedTransactionPressed),
        );
    }

    container(
        column![
            section_heading(
                "Broadcast signed transaction",
                "Load a signed response from the offline machine and submit it through the selected RPC provider."
            ),
            network,
            response_input,
            broadcast_state_view(&app.broadcast_state),
            actions,
        ]
        .spacing(24)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn online_sign_view(app: &OnlineApp) -> Element<'_, Message> {
    let known_accounts: Vec<String> = app
        .account_directory
        .iter()
        .filter(|(_, keys)| keys.iter().any(|entry| entry.network == app.network))
        .map(|(account_id, _)| account_id.clone())
        .collect();
    let selected_signer_account = known_accounts
        .iter()
        .find(|account_id| account_id.as_str() == app.signer_id.trim())
        .cloned();
    let selected_receiver_account = known_accounts
        .iter()
        .find(|account_id| account_id.as_str() == app.receiver_id.trim())
        .cloned();
    let signer_public_keys: Vec<String> = app
        .account_directory
        .get(app.signer_id.trim())
        .map(|keys| {
            keys.iter()
                .filter(|entry| entry.network == app.network)
                .map(|entry| entry.public_key.clone())
                .collect()
        })
        .unwrap_or_default();
    let selected_signer_public_key = signer_public_keys
        .iter()
        .find(|public_key| public_key.as_str() == app.signer_public_key.trim())
        .cloned();

    let network = column![
        text("Network").size(14),
        pick_list(
            [Network::Testnet, Network::Mainnet],
            Some(app.network),
            Message::NetworkChanged
        )
        .width(Length::Fill),
    ]
    .spacing(8);

    let chain_state = column![
        row![
            field("Nonce", &app.nonce, Message::NonceChanged),
            field("Recent block hash", &app.block_hash, Message::BlockHashChanged),
        ]
        .spacing(16),
        row![
            button(text("Fetch").size(16))
                .padding([12, 18])
                .on_press(Message::FetchChainStatePressed),
            chain_state_view(&app.status),
        ]
        .spacing(16)
        .align_y(Alignment::Center),
    ]
    .spacing(12);

    let form = column![
        network,
        signer_account_field(&app.signer_id, known_accounts.clone(), selected_signer_account,),
        signer_public_key_field(&app.signer_public_key, signer_public_keys, selected_signer_public_key,),
        receiver_account_field(&app.receiver_id, known_accounts, selected_receiver_account,),
        field("Deposit in NEAR", &app.deposit_near, Message::DepositChanged),
        chain_state,
        field("Output file", &app.output, Message::OutputChanged),
    ]
    .spacing(16)
    .width(Length::Fill);

    let mut generate_button = button(text("Generate").size(16)).padding([12, 18]);
    if app.can_generate() {
        generate_button = generate_button.on_press(Message::GeneratePressed);
    }

    let actions = column![
        status_view(&app.status),
        row![generate_button].spacing(16).align_y(Alignment::Center),
    ]
    .spacing(12)
    .width(Length::Fill);

    container(
        column![
            section_heading(
                "Create transfer request",
                "Prepare a NEAR transfer payload for the offline signer with saved accounts, chain state lookup, and export path controls."
            ),
            form,
            actions,
        ]
        .spacing(28)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn online_accounts_view(app: &OnlineApp) -> Element<'_, Message> {
    let network = column![
        text("Network").size(14),
        pick_list(
            [Network::Testnet, Network::Mainnet],
            Some(app.network),
            Message::NetworkChanged
        )
        .width(Length::Fill),
    ]
    .spacing(8);

    let lookup = row![
        text_input("Account", &app.account_lookup)
            .on_input(Message::AccountLookupChanged)
            .padding(12)
            .size(16)
            .width(Length::Fill),
        button(text("Load Keys").size(16))
            .padding([12, 18])
            .on_press(Message::FetchAccountKeysPressed),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    let table = online_accounts_table(&app.account_directory);

    let mut refresh_button = button(text("Refresh").size(16)).padding([10, 18]);
    if !app.account_directory.is_empty() {
        refresh_button = refresh_button.on_press(Message::RefreshAccountKeysPressed);
    }

    let mut cleanup_button = button(text("Cleanup").size(16)).padding([10, 18]);
    if !app.account_directory.is_empty() {
        cleanup_button = cleanup_button.on_press(Message::CleanupAccountKeysPressed);
    }

    let table_actions = row![refresh_button, cleanup_button]
        .spacing(12)
        .align_y(Alignment::Center);

    container(
        column![
            section_heading(
                "Saved accounts",
                "Cache account ids and load their access keys from the selected network and provider."
            ),
            network,
            column![text("Account").size(14), lookup].spacing(8),
            table,
            table_actions,
            account_status_view(&app.account_status),
        ]
        .spacing(24)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn online_view_account_view(app: &OnlineApp) -> Element<'_, Message> {
    let network = column![
        text("Network").size(14),
        pick_list(
            [Network::Testnet, Network::Mainnet],
            Some(app.network),
            Message::NetworkChanged
        )
        .width(Length::Fill),
    ]
    .spacing(8);

    let lookup = row![
        text_input("Account", &app.view_account_lookup)
            .on_input(Message::ViewAccountLookupChanged)
            .padding(12)
            .size(16)
            .width(Length::Fill),
        button(text("View Account").size(16))
            .padding([12, 18])
            .on_press(Message::FetchViewAccountPressed),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    container(
        column![
            section_heading(
                "View account",
                "Inspect the live native balance and access keys for any account through the selected RPC provider."
            ),
            network,
            column![text("Account").size(14), lookup].spacing(8),
            view_account_state_view(&app.view_account_state),
        ]
        .spacing(24)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn online_del_keys_view(app: &OnlineApp) -> Element<'_, Message> {
    let known_accounts: Vec<String> = app
        .account_directory
        .iter()
        .filter(|(_, keys)| keys.iter().any(|entry| entry.network == app.network))
        .map(|(account_id, _)| account_id.clone())
        .collect();
    let selected_signer_account = known_accounts
        .iter()
        .find(|account_id| account_id.as_str() == app.signer_id.trim())
        .cloned();
    let signer_public_keys: Vec<String> = app
        .account_directory
        .get(app.signer_id.trim())
        .map(|keys| {
            keys.iter()
                .filter(|entry| entry.network == app.network)
                .map(|entry| entry.public_key.clone())
                .collect()
        })
        .unwrap_or_default();
    let selected_signer_public_key = signer_public_keys
        .iter()
        .find(|public_key| public_key.as_str() == app.signer_public_key.trim())
        .cloned();
    let selected_delete_key_public_key = signer_public_keys
        .iter()
        .find(|public_key| public_key.as_str() == app.delete_key_public_key.trim())
        .cloned();

    let network = column![
        text("Network").size(14),
        pick_list(
            [Network::Testnet, Network::Mainnet],
            Some(app.network),
            Message::NetworkChanged
        )
        .width(Length::Fill),
    ]
    .spacing(8);

    let chain_state = column![
        row![
            field("Nonce", &app.nonce, Message::NonceChanged),
            field("Recent block hash", &app.block_hash, Message::BlockHashChanged),
        ]
        .spacing(16),
        row![
            button(text("Fetch").size(16))
                .padding([12, 18])
                .on_press(Message::FetchChainStatePressed),
            chain_state_view(&app.status),
        ]
        .spacing(16)
        .align_y(Alignment::Center),
    ]
    .spacing(12);

    let form = column![
        network,
        signer_account_field(&app.signer_id, known_accounts, selected_signer_account),
        signer_public_key_field(
            &app.signer_public_key,
            signer_public_keys.clone(),
            selected_signer_public_key
        ),
        delete_key_public_key_field(
            &app.delete_key_public_key,
            signer_public_keys,
            selected_delete_key_public_key,
        ),
        chain_state,
        field("Output file", &app.output, Message::OutputChanged),
    ]
    .spacing(16)
    .width(Length::Fill);

    let mut generate_button = button(text("Generate").size(16)).padding([12, 18]);
    if app.can_generate() {
        generate_button = generate_button.on_press(Message::GeneratePressed);
    }

    container(
        column![
            section_heading(
                "Create delete-key request",
                "Prepare a NEAR delete-key payload for the offline signer so a specific public key can be removed from the signer account."
            ),
            text("The delete-key action targets the signer account itself and removes the selected public key from that account.")
                .size(14)
                .color(Color::from_rgb8(95, 103, 120)),
            form,
            column![
                status_view(&app.status),
                row![generate_button].spacing(16).align_y(Alignment::Center),
            ]
            .spacing(12)
            .width(Length::Fill),
        ]
        .spacing(28)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn online_add_key_view(app: &OnlineApp) -> Element<'_, Message> {
    let known_accounts: Vec<String> = app
        .account_directory
        .iter()
        .filter(|(_, keys)| keys.iter().any(|entry| entry.network == app.network))
        .map(|(account_id, _)| account_id.clone())
        .collect();
    let selected_signer_account = known_accounts
        .iter()
        .find(|account_id| account_id.as_str() == app.signer_id.trim())
        .cloned();
    let signer_public_keys: Vec<String> = app
        .account_directory
        .get(app.signer_id.trim())
        .map(|keys| {
            keys.iter()
                .filter(|entry| entry.network == app.network)
                .map(|entry| entry.public_key.clone())
                .collect()
        })
        .unwrap_or_default();
    let selected_signer_public_key = signer_public_keys
        .iter()
        .find(|public_key| public_key.as_str() == app.signer_public_key.trim())
        .cloned();

    let network = column![
        text("Network").size(14),
        pick_list(
            [Network::Testnet, Network::Mainnet],
            Some(app.network),
            Message::NetworkChanged
        )
        .width(Length::Fill),
    ]
    .spacing(8);

    let chain_state = column![
        row![
            field("Nonce", &app.nonce, Message::NonceChanged),
            field("Recent block hash", &app.block_hash, Message::BlockHashChanged),
        ]
        .spacing(16),
        row![
            button(text("Fetch").size(16))
                .padding([12, 18])
                .on_press(Message::FetchChainStatePressed),
            chain_state_view(&app.status),
        ]
        .spacing(16)
        .align_y(Alignment::Center),
    ]
    .spacing(12);

    let form = column![
        network,
        signer_account_field(&app.signer_id, known_accounts, selected_signer_account),
        signer_public_key_field(&app.signer_public_key, signer_public_keys, selected_signer_public_key),
        field(
            "Add public key",
            &app.add_key_public_key,
            Message::AddKeyPublicKeyChanged
        ),
        chain_state,
        field("Output file", &app.output, Message::OutputChanged),
    ]
    .spacing(16)
    .width(Length::Fill);

    let mut generate_button = button(text("Generate").size(16)).padding([12, 18]);
    if app.can_generate() {
        generate_button = generate_button.on_press(Message::GeneratePressed);
    }

    container(
        column![
            section_heading(
                "Create add-key request",
                "Prepare a NEAR add-key payload for the offline signer so a new full-access public key can be attached to the signer account."
            ),
            text("The add-key action targets the signer account itself and adds the provided public key with FullAccess permission.")
                .size(14)
                .color(Color::from_rgb8(95, 103, 120)),
            form,
            column![
                status_view(&app.status),
                row![generate_button].spacing(16).align_y(Alignment::Center),
            ]
            .spacing(12)
            .width(Length::Fill),
        ]
        .spacing(28)
        .width(Length::Fill),
    )
    .padding(28)
    .width(Length::Fill)
    .style(|_| card_style())
    .into()
}

fn hero_section(active_tab: Tab) -> Element<'static, Message> {
    let (eyebrow, title, subtitle) = match active_tab {
        Tab::Sign => (
            "ONLINE PREP",
            "Create transfer requests with a cleaner top-level flow",
            "Keep app controls in the header, fill the transaction details in one focused card, then hand the file to the offline signer.",
        ),
        Tab::SignDelKeys => (
            "ONLINE PREP",
            "Generate delete-key requests for offline signing",
            "Build a request that removes a specific public key from an account, then move that file to the offline signer for approval and signing.",
        ),
        Tab::SignAddKey => (
            "ONLINE PREP",
            "Generate add-key requests for offline signing",
            "Build a request that adds a new full-access public key to an account, then move that file to the offline signer for approval and signing.",
        ),
        Tab::Broadcast => (
            "ONLINE BROADCAST",
            "Review and submit signed transactions",
            "Load a signed response, verify the decoded transaction details, and broadcast through your selected provider.",
        ),
        Tab::ViewKnownAccount => (
            "ACCOUNT DIRECTORY",
            "Keep saved accounts and public keys within reach",
            "Build a reusable account directory so signer and receiver inputs are faster and less error-prone.",
        ),
        Tab::ViewAccount => (
            "ACCOUNT INSPECTOR",
            "View live balances and access keys",
            "Look up a NEAR account through the selected RPC provider and review its native balance plus the current access-key list.",
        ),
    };

    container(
        column![
            text(eyebrow).size(13).color(Color::from_rgb8(72, 110, 255)),
            text(title).size(36),
            text(subtitle).size(16).color(Color::from_rgb8(95, 103, 120)),
        ]
        .spacing(10)
        .max_width(720),
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
            top_tab_button("View-Account", Tab::ViewAccount, active_tab),
            top_tab_button("View-KnownAccount", Tab::ViewKnownAccount, active_tab),
            top_tab_button("Gen-Transfer", Tab::Sign, active_tab),
            top_tab_button("Gen-AddKey", Tab::SignAddKey, active_tab),
            top_tab_button("Gen-DelKey", Tab::SignDelKeys, active_tab),
            top_tab_button("Broadcast", Tab::Broadcast, active_tab),
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

fn copy_icon_button<'a>() -> iced::widget::Button<'a, Message> {
    button(
        svg(svg::Handle::from_path(COPY_ICON_PATH))
            .width(Length::Fixed(16.0))
            .height(Length::Fixed(16.0)),
    )
    .padding([6, 10])
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

fn signer_account_field<'a>(
    value: &'a str,
    known_accounts: Vec<String>,
    selected_account: Option<String>,
) -> Element<'a, Message> {
    let helper = if known_accounts.is_empty() {
        text("No saved accounts yet. Add them in Accounts to use the helper dropdown.").size(13)
    } else {
        text("Known accounts").size(13)
    };

    let picker: Element<'a, Message> = if known_accounts.is_empty() {
        container(text("Known accounts will appear here after you load them in Accounts.").size(14))
            .padding([10, 12])
            .width(Length::Fill)
            .into()
    } else {
        pick_list(known_accounts, selected_account, Message::SignerKnownAccountSelected)
            .placeholder("Select a saved account")
            .width(Length::Fill)
            .into()
    };

    column![
        text("Signer account").size(14),
        row![
            text_input("Signer account", value)
                .on_input(Message::SignerIdChanged)
                .padding(12)
                .size(16)
                .width(Length::Fill),
            picker,
        ]
        .spacing(12)
        .align_y(Alignment::Center),
        helper,
    ]
    .spacing(8)
    .width(Length::Fill)
    .into()
}

fn signer_public_key_field<'a>(
    value: &'a str,
    known_public_keys: Vec<String>,
    selected_public_key: Option<String>,
) -> Element<'a, Message> {
    let helper = if known_public_keys.is_empty() {
        text("No saved public keys for this signer account yet.").size(13)
    } else {
        text("Known public keys for this signer").size(13)
    };

    let picker: Element<'a, Message> = if known_public_keys.is_empty() {
        container(text("Load this account in Accounts to use the public key selector.").size(14))
            .padding([10, 12])
            .width(Length::Fill)
            .into()
    } else {
        pick_list(
            known_public_keys,
            selected_public_key,
            Message::SignerKnownPublicKeySelected,
        )
        .placeholder("Select a saved public key")
        .width(Length::Fill)
        .into()
    };

    column![
        text("Signer public key").size(14),
        row![
            text_input("Signer public key", value)
                .on_input(Message::SignerPublicKeyChanged)
                .padding(12)
                .size(16)
                .width(Length::Fill),
            picker,
        ]
        .spacing(12)
        .align_y(Alignment::Center),
        helper,
    ]
    .spacing(8)
    .width(Length::Fill)
    .into()
}

fn delete_key_public_key_field<'a>(
    value: &'a str,
    known_public_keys: Vec<String>,
    selected_public_key: Option<String>,
) -> Element<'a, Message> {
    let helper = if known_public_keys.is_empty() {
        text("No saved public keys for this signer account yet.").size(13)
    } else {
        text("Known public keys that can be removed from this signer").size(13)
    };

    let picker: Element<'a, Message> = if known_public_keys.is_empty() {
        container(text("Load this account in Accounts to select the key you want to delete.").size(14))
            .padding([10, 12])
            .width(Length::Fill)
            .into()
    } else {
        pick_list(
            known_public_keys,
            selected_public_key,
            Message::DeleteKeyKnownPublicKeySelected,
        )
        .placeholder("Select a saved public key to delete")
        .width(Length::Fill)
        .into()
    };

    column![
        text("Delete public key").size(14),
        row![
            text_input("Delete public key", value)
                .on_input(Message::DeleteKeyPublicKeyChanged)
                .padding(12)
                .size(16)
                .width(Length::Fill),
            picker,
        ]
        .spacing(12)
        .align_y(Alignment::Center),
        helper,
    ]
    .spacing(8)
    .width(Length::Fill)
    .into()
}

fn receiver_account_field<'a>(
    value: &'a str,
    known_accounts: Vec<String>,
    selected_account: Option<String>,
) -> Element<'a, Message> {
    let helper = if known_accounts.is_empty() {
        text("No saved accounts yet. Add them in Accounts to use the helper dropdown.").size(13)
    } else {
        text("Known accounts").size(13)
    };

    let picker: Element<'a, Message> = if known_accounts.is_empty() {
        container(text("Known accounts will appear here after you load them in Accounts.").size(14))
            .padding([10, 12])
            .width(Length::Fill)
            .into()
    } else {
        pick_list(known_accounts, selected_account, Message::ReceiverKnownAccountSelected)
            .placeholder("Select a saved account")
            .width(Length::Fill)
            .into()
    };

    column![
        text("Receiver account").size(14),
        row![
            text_input("Receiver account", value)
                .on_input(Message::ReceiverIdChanged)
                .padding(12)
                .size(16)
                .width(Length::Fill),
            picker,
        ]
        .spacing(12)
        .align_y(Alignment::Center),
        helper,
    ]
    .spacing(8)
    .width(Length::Fill)
    .into()
}

fn online_accounts_table<'a>(
    account_directory: &'a BTreeMap<String, Vec<AccountAccessKeyRow>>,
) -> Element<'a, Message> {
    let header = row![
        container(text("Account").size(14)).width(Length::Fixed(ACCOUNT_COLUMN_WIDTH)),
        container(text("Network").size(14)).width(Length::Fixed(NETWORK_COLUMN_WIDTH)),
        container(text("Permission").size(14)).width(Length::Fixed(PERMISSION_COLUMN_WIDTH)),
        container(text("Public Key").size(14)).width(Length::Fill),
        container(text("Action").size(14)).width(Length::Fixed(ACTION_COLUMN_WIDTH)),
    ]
    .spacing(16)
    .align_y(Alignment::Center);

    let rows = account_directory
        .iter()
        .flat_map(|(account_id, keys)| {
            keys.iter().map(move |entry| {
                let public_key = entry.public_key.clone();
                column![
                    row![
                        container(text(account_id.as_str()).size(14)).width(Length::Fixed(ACCOUNT_COLUMN_WIDTH)),
                        container(text(entry.network.to_string()).size(14)).width(Length::Fixed(NETWORK_COLUMN_WIDTH)),
                        container(text(entry.permission_label.as_str()).size(14))
                            .width(Length::Fixed(PERMISSION_COLUMN_WIDTH)),
                        container(text(short_public_key(entry.public_key.as_str())).size(14)).width(Length::Fill),
                        container(
                            button(
                                svg(svg::Handle::from_path(DELETE_ICON_PATH))
                                    .width(Length::Fixed(16.0))
                                    .height(Length::Fixed(16.0))
                            )
                            .padding([6, 10])
                            .style(iced::widget::button::text)
                            .on_press(Message::DeleteSavedAccountKeyPressed {
                                account_id: account_id.clone(),
                                network: entry.network,
                                public_key,
                            })
                        )
                        .width(Length::Fixed(ACTION_COLUMN_WIDTH)),
                    ]
                    .spacing(16)
                    .align_y(Alignment::Center),
                    table_divider(),
                ]
                .spacing(12)
            })
        })
        .fold(
            column![table_divider(), header, table_divider()].spacing(12),
            |table, row| table.push(row),
        );

    column![text("Saved Accounts").size(20), rows]
        .spacing(12)
        .width(Length::Fill)
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

fn table_divider<'a>() -> Element<'a, Message> {
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

fn account_status_view(status: &AccountStatus) -> Element<'_, Message> {
    match status {
        AccountStatus::Idle => text("Load an account to inspect all access keys from RPC.")
            .size(15)
            .into(),
        AccountStatus::Fetching => text("Loading account keys from RPC...").size(15).into(),
        AccountStatus::Loaded { account_id, key_count } => {
            let message = if *key_count == 0 {
                format!(
                    "Loaded 0 access key(s) for {account_id}. Check that the selected network matches this account."
                )
            } else {
                format!("Loaded {key_count} access key(s) for {account_id}.")
            };

            status_notice(message, true)
        }
        AccountStatus::Refreshed {
            account_count,
            key_count,
        } => {
            let message =
                format!("Refreshed {account_count} saved account(s) and loaded {key_count} access key(s) from RPC.");

            status_notice(message, true)
        }
        AccountStatus::Error(error) => status_notice(format!("Error: {error}"), false),
    }
}

fn view_account_state_view(state: &ViewAccountState) -> Element<'_, Message> {
    match state {
        ViewAccountState::Idle => text("Load an account to inspect its native balance and access keys from RPC.")
            .size(15)
            .into(),
        ViewAccountState::Fetching => text("Loading account summary from RPC...").size(15).into(),
        ViewAccountState::Loaded(account) => {
            let key_rows: Vec<Element<'_, Message>> = if account.keys.is_empty() {
                vec![text("No access keys found.").size(14).into()]
            } else {
                account
                    .keys
                    .iter()
                    .map(|key| {
                        row![
                            container(text(key.public_key.as_str()).size(13)).width(Length::FillPortion(5)),
                            container(text(key.nonce.to_string()).size(13)).width(Length::FillPortion(2)),
                            container(text(key.permission_label.as_str()).size(13)).width(Length::FillPortion(2)),
                        ]
                        .spacing(12)
                        .into()
                    })
                    .collect()
            };

            container(
                column![
                    text("Account summary").size(15),
                    text(format!("account: {}", account.account_id)).size(13),
                    text(format!(
                        "native account balance: {} NEAR",
                        format_yocto_near(account.native_balance_yocto_near)
                    ))
                    .size(13),
                    table_divider(),
                    row![
                        container(text("Public Key").size(13)).width(Length::FillPortion(5)),
                        container(text("Nonce").size(13)).width(Length::FillPortion(2)),
                        container(text("Permission").size(13)).width(Length::FillPortion(2)),
                    ]
                    .spacing(12),
                    column(key_rows).spacing(8),
                ]
                .spacing(10),
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
        ViewAccountState::Error(error) => status_notice(format!("Error: {error}"), false),
    }
}

fn status_notice(message: String, success: bool) -> Element<'static, Message> {
    let (border_color, background_color) = if success {
        (Color::from_rgb8(34, 197, 94), Color::from_rgb8(240, 253, 244))
    } else {
        (Color::from_rgb8(239, 68, 68), Color::from_rgb8(254, 242, 242))
    };

    container(text(message).size(15))
        .padding(16)
        .width(Length::Fill)
        .style(move |_| iced::widget::container::Style {
            border: Border {
                width: 1.0,
                radius: 10.0.into(),
                color: border_color,
            },
            background: Some(background_color.into()),
            text_color: None,
            shadow: iced::Shadow::default(),
            snap: false,
        })
        .into()
}

fn status_view(status: &Status) -> Element<'_, Message> {
    match status {
        Status::Idle | Status::Fetching | Status::Fetched(_) => text("Ready").size(15).into(),
        Status::Success(result) => {
            let request_id = result.id.clone();
            let absolute_path = result.output.display().to_string();

            container(
                column![
                    text("Request file created").size(15),
                    text(format!("id: {request_id}")).size(13),
                    row![
                        text(format!("path: {absolute_path}")).size(13),
                        copy_icon_button().on_press(Message::CopyPressed(absolute_path)),
                    ]
                    .spacing(10)
                    .align_y(Alignment::Center),
                    table_divider(),
                    text("Edit any field to generate again.").size(13),
                ]
                .spacing(8),
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
            .into()
        }
        Status::Error(error) => text(format!("Error: {error}"))
            .size(15)
            .align_x(alignment::Horizontal::Center)
            .into(),
    }
}

fn chain_state_view(status: &Status) -> Element<'_, Message> {
    match status {
        Status::Fetching => text("Fetching nonce and block hash...").size(15).into(),
        Status::Fetched(chain_state) => column![
            text("Loaded from RPC").size(15),
            text(format!("next nonce: {}", chain_state.next_nonce)).size(13),
            text(format!("block hash: {}", chain_state.block_hash)).size(13),
        ]
        .spacing(4)
        .into(),
        Status::Error(error) => text(format!("Error: {error}"))
            .size(15)
            .align_x(alignment::Horizontal::Center)
            .into(),
        Status::Idle | Status::Success(_) => text("Nonce and block hash can be fetched from RPC.").size(15).into(),
    }
}

fn broadcast_state_view(state: &BroadcastState) -> Element<'_, Message> {
    let content: Element<'_, Message> = match state {
        BroadcastState::Idle => text("Load a signed response file to inspect and broadcast it.")
            .size(15)
            .into(),
        BroadcastState::Loading => text("Loading signed response...").size(15).into(),
        BroadcastState::Loaded(loaded) => {
            let action_details = match &loaded.action {
                SignedActionSummary::Transfer {
                    receiver_id,
                    deposit_yocto_near,
                } => column![
                    text("type: Transfer").size(13),
                    text(format!("receiver: {receiver_id}")).size(13),
                    text(format!("deposit: {} NEAR", format_yocto_near(*deposit_yocto_near))).size(13),
                ]
                .spacing(4),
                SignedActionSummary::DeleteKey {
                    receiver_id,
                    delete_public_key,
                } => column![
                    text("type: DeleteKey").size(13),
                    text(format!("account: {receiver_id}")).size(13),
                    text(format!("delete public key: {delete_public_key}")).size(13),
                ]
                .spacing(4),
                SignedActionSummary::AddKey {
                    receiver_id,
                    add_public_key,
                    permission,
                } => column![
                    text("type: AddKey").size(13),
                    text(format!("account: {receiver_id}")).size(13),
                    text(format!("add public key: {add_public_key}")).size(13),
                    text(format!("permission: {permission}")).size(13),
                ]
                .spacing(4),
            };

            column![
                text("Signed transaction loaded").size(15),
                text(format!("request id: {}", loaded.request_id)).size(13),
                text(format!("transaction hash: {}", loaded.transaction_hash)).size(13),
                text(format!("signer: {}", loaded.signer_id)).size(13),
                action_details,
                text(format!("nonce: {}", loaded.nonce)).size(13),
                text(format!("public key: {}", loaded.public_key)).size(13),
                text(format!("signature: {}", loaded.signature)).size(13),
            ]
            .spacing(4)
            .into()
        }
        BroadcastState::Broadcasting => text("Broadcasting transaction...").size(15).into(),
        BroadcastState::Broadcasted(result) => column![
            text("Transaction broadcasted").size(15),
            text(format!("transaction hash: {}", result.transaction_hash)).size(13),
            text(format!("final execution status: {}", result.final_execution_status)).size(13),
        ]
        .spacing(4)
        .into(),
        BroadcastState::Error(error) => text(format!("Error: {error}"))
            .size(15)
            .align_x(alignment::Horizontal::Center)
            .into(),
    };

    container(content)
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

fn parse_u64(field: &'static str, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse()
        .map_err(|error| format!("{field} must be a number: {error}"))
}

fn parse_near_amount(value: &str) -> Result<Balance, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("deposit is required".to_owned());
    }

    let (whole, fractional) = match trimmed.split_once('.') {
        Some((whole, fractional)) => (whole, fractional),
        None => (trimmed, ""),
    };

    if whole.is_empty() && fractional.is_empty() {
        return Err("deposit must be a NEAR amount".to_owned());
    }

    if !whole.chars().all(|ch| ch.is_ascii_digit()) || !fractional.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("deposit must be a NEAR amount, like 0.5 or 1".to_owned());
    }

    if fractional.len() > 24 {
        return Err("deposit supports at most 24 decimal places".to_owned());
    }

    let whole = if whole.is_empty() { "0" } else { whole };
    let whole_yocto = whole
        .parse::<u128>()
        .map_err(|error| format!("deposit is too large: {error}"))?
        .checked_mul(10_u128.pow(24))
        .ok_or_else(|| "deposit is too large".to_owned())?;

    let mut fractional_padded = fractional.to_owned();
    fractional_padded.extend(std::iter::repeat_n('0', 24 - fractional.len()));

    let fractional_yocto = if fractional_padded.is_empty() {
        0
    } else {
        fractional_padded
            .parse::<u128>()
            .map_err(|error| format!("deposit fractional part is invalid: {error}"))?
    };

    let yocto = whole_yocto
        .checked_add(fractional_yocto)
        .ok_or_else(|| "deposit is too large".to_owned())?;

    Ok(Balance::from_yoctonear(yocto))
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

fn format_yocto_near(amount: u128) -> String {
    let whole = amount / 10_u128.pow(24);
    let fractional = amount % 10_u128.pow(24);
    if fractional == 0 {
        return whole.to_string();
    }

    let fractional = format!("{fractional:024}");
    let fractional = fractional.trim_end_matches('0');
    format!("{whole}.{fractional}")
}

#[derive(Debug)]
enum Status {
    Idle,
    Fetching,
    Fetched(ChainState),
    Success(GeneratedRequest),
    Error(String),
}

#[derive(Debug, Clone)]
struct ChainState {
    next_nonce: u64,
    block_hash: String,
}

#[derive(Debug)]
struct GeneratedRequest {
    id: String,
    output: PathBuf,
    snapshot: RequestSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestSnapshot {
    active_tab: Tab,
    network: Network,
    signer_id: String,
    signer_public_key: String,
    delete_key_public_key: String,
    add_key_public_key: String,
    receiver_id: String,
    nonce: String,
    block_hash: String,
    deposit_near: String,
    output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountAccessKeyRow {
    #[serde(default = "default_account_network")]
    network: Network,
    public_key: String,
    permission_label: String,
}

#[derive(Debug, Clone)]
struct LoadedAccountKeys {
    network: Network,
    account_id: String,
    rows: Vec<AccountAccessKeyRow>,
}

#[derive(Debug, Clone)]
struct LoadedAccountDirectory {
    network: Network,
    accounts: BTreeMap<String, Vec<AccountAccessKeyRow>>,
    key_count: usize,
}

#[derive(Debug, Clone)]
enum BroadcastState {
    Idle,
    Loading,
    Loaded(LoadedSignedResponse),
    Broadcasting,
    Broadcasted(BroadcastResult),
    Error(String),
}

#[derive(Debug, Clone)]
struct LoadedSignedResponse {
    request_id: String,
    transaction_hash: String,
    signer_id: String,
    nonce: u64,
    action: SignedActionSummary,
    public_key: String,
    signature: String,
    signed_tx_base64: String,
}

#[derive(Debug, Clone)]
enum SignedActionSummary {
    Transfer {
        receiver_id: String,
        deposit_yocto_near: u128,
    },
    DeleteKey {
        receiver_id: String,
        delete_public_key: String,
    },
    AddKey {
        receiver_id: String,
        add_public_key: String,
        permission: String,
    },
}

#[derive(Debug, Clone)]
struct BroadcastResult {
    transaction_hash: String,
    final_execution_status: String,
}

#[derive(Debug)]
enum AccountStatus {
    Idle,
    Fetching,
    Loaded { account_id: String, key_count: usize },
    Refreshed { account_count: usize, key_count: usize },
    Error(String),
}

#[derive(Debug, Clone)]
struct ViewAccountData {
    account_id: String,
    native_balance_yocto_near: u128,
    keys: Vec<ViewAccountKeyRow>,
}

#[derive(Debug, Clone)]
struct ViewAccountKeyRow {
    public_key: String,
    nonce: u64,
    permission_label: String,
}

#[derive(Debug, Clone)]
enum ViewAccountState {
    Idle,
    Fetching,
    Loaded(ViewAccountData),
    Error(String),
}

async fn fetch_chain_state(
    network: Network,
    provider: ProviderKind,
    account_id: String,
    public_key: String,
) -> Result<ChainState, String> {
    if account_id.is_empty() {
        return Err("signer account is required before fetching chain state".to_owned());
    }

    if public_key.is_empty() {
        return Err("signer public key is required before fetching chain state".to_owned());
    }

    let endpoint = rpc_endpoint(network, provider);
    let rpc_name = rpc_name(network, provider);
    let client = reqwest::blocking::Client::new();

    let access_key: RpcResponse<ViewAccessKeyResult> = post_rpc(
        &client,
        &rpc_name,
        &endpoint,
        RpcRequest {
            jsonrpc: "2.0",
            id: "access-key",
            method: "query",
            params: QueryAccessKeyParams {
                request_type: "view_access_key",
                finality: "final",
                account_id: &account_id,
                public_key: &public_key,
            },
        },
    )?;

    let block: RpcResponse<BlockResult> = post_rpc(
        &client,
        &rpc_name,
        &endpoint,
        RpcRequest {
            jsonrpc: "2.0",
            id: "block",
            method: "block",
            params: BlockParams { finality: "final" },
        },
    )?;

    Ok(ChainState {
        next_nonce: access_key
            .result
            .nonce
            .checked_add(1)
            .ok_or_else(|| "access key nonce is too large".to_owned())?,
        block_hash: block.result.header.hash,
    })
}

async fn load_signed_response(path: String) -> Result<LoadedSignedResponse, String> {
    if path.is_empty() {
        return Err("signed response file path is required".to_owned());
    }

    let content = fs::read_to_string(&path).map_err(|error| format!("failed to read signed response file: {error}"))?;
    let response: SignedTransactionResponse = response_from_json(&content).map_err(|error| error.to_string())?;
    let signed_bytes = STANDARD
        .decode(&response.signed_transaction_borsh_base64)
        .map_err(|error| format!("failed to decode signed transaction base64: {error}"))?;
    let signed_tx: SignedTransaction =
        from_slice(&signed_bytes).map_err(|error| format!("failed to decode signed transaction: {error}"))?;

    let derived_public_key = signed_tx.transaction.public_key().to_string();
    if derived_public_key != response.public_key {
        return Err(format!(
            "signed response public key {} does not match transaction public key {}",
            response.public_key, derived_public_key
        ));
    }

    let derived_signature = signed_tx.signature.to_string();
    if derived_signature != response.signature {
        return Err(format!(
            "signed response signature {} does not match transaction signature {}",
            response.signature, derived_signature
        ));
    }

    let Transaction::V0(transaction) = &signed_tx.transaction else {
        return Err("only V0 signed transactions are supported".to_owned());
    };
    let action = match transaction.actions.as_slice() {
        [Action::Transfer(transfer)] => SignedActionSummary::Transfer {
            receiver_id: transaction.receiver_id.to_string(),
            deposit_yocto_near: transfer.deposit.as_yoctonear(),
        },
        [Action::DeleteKey(delete_key)] => SignedActionSummary::DeleteKey {
            receiver_id: transaction.receiver_id.to_string(),
            delete_public_key: delete_key.public_key.to_string(),
        },
        [Action::AddKey(add_key)] => SignedActionSummary::AddKey {
            receiver_id: transaction.receiver_id.to_string(),
            add_public_key: add_key.public_key.to_string(),
            permission: "FullAccess".to_owned(),
        },
        _ => {
            return Err(
                "only single-action transfer, delete-key, or full-access add-key transactions are supported".to_owned(),
            );
        }
    };

    Ok(LoadedSignedResponse {
        request_id: response.request_id,
        transaction_hash: signed_tx.get_hash().to_string(),
        signer_id: transaction.signer_id.to_string(),
        nonce: transaction.nonce,
        action,
        public_key: response.public_key,
        signature: response.signature,
        signed_tx_base64: response.signed_transaction_borsh_base64,
    })
}

async fn broadcast_signed_transaction(
    network: Network,
    provider: ProviderKind,
    loaded: LoadedSignedResponse,
) -> Result<BroadcastResult, String> {
    let endpoint = rpc_endpoint(network, provider);
    let rpc_name = rpc_name(network, provider);
    let client = reqwest::blocking::Client::new();

    let result: Value = post_rpc(
        &client,
        &rpc_name,
        &endpoint,
        RpcRequest {
            jsonrpc: "2.0",
            id: "broadcast-tx",
            method: "broadcast_tx_commit",
            params: BroadcastTxParams {
                signed_tx_base64: &loaded.signed_tx_base64,
                wait_until: "EXECUTED_OPTIMISTIC",
            },
        },
    )?
    .result;

    let transaction_hash = result
        .get("transaction")
        .and_then(|value| value.get("hash"))
        .and_then(Value::as_str)
        .or_else(|| {
            result
                .get("transaction_outcome")
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
        })
        .unwrap_or(loaded.transaction_hash.as_str())
        .to_owned();

    let final_execution_status = result
        .get("final_execution_status")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN")
        .to_owned();

    Ok(BroadcastResult {
        transaction_hash,
        final_execution_status,
    })
}

async fn fetch_account_keys(
    network: Network,
    provider: ProviderKind,
    account_id: String,
) -> Result<LoadedAccountKeys, String> {
    let account_id = account_id.trim().to_owned();
    if account_id.is_empty() {
        return Err("account is required before loading keys".to_owned());
    }

    let endpoint = rpc_endpoint(network, provider);
    let rpc_name = rpc_name(network, provider);
    let client = reqwest::blocking::Client::new();

    let access_keys: RpcResponse<ViewAccessKeyListResult> = post_rpc(
        &client,
        &rpc_name,
        &endpoint,
        RpcRequest {
            jsonrpc: "2.0",
            id: "access-key-list",
            method: "query",
            params: QueryAccessKeyListParams {
                request_type: "view_access_key_list",
                finality: "final",
                account_id: &account_id,
            },
        },
    )?;

    let rows = access_keys
        .result
        .keys
        .into_iter()
        .map(|key| AccountAccessKeyRow {
            network,
            public_key: key.public_key,
            permission_label: match key.access_key.permission {
                PermissionView::FullAccess => "full access".to_owned(),
                PermissionView::FunctionCall { .. } => "function call".to_owned(),
            },
        })
        .collect();

    Ok(LoadedAccountKeys {
        network,
        account_id,
        rows,
    })
}

async fn fetch_view_account(
    network: Network,
    provider: ProviderKind,
    account_id: String,
) -> Result<ViewAccountData, String> {
    let account_id = account_id.trim().to_owned();
    if account_id.is_empty() {
        return Err("account is required before loading account details".to_owned());
    }

    let endpoint = rpc_endpoint(network, provider);
    let rpc_name = rpc_name(network, provider);
    let client = reqwest::blocking::Client::new();

    let account: RpcResponse<ViewAccountResult> = post_rpc(
        &client,
        &rpc_name,
        &endpoint,
        RpcRequest {
            jsonrpc: "2.0",
            id: "view-account",
            method: "query",
            params: QueryViewAccountParams {
                request_type: "view_account",
                finality: "final",
                account_id: &account_id,
            },
        },
    )?;

    let access_keys: RpcResponse<ViewAccessKeyListResult> = post_rpc(
        &client,
        &rpc_name,
        &endpoint,
        RpcRequest {
            jsonrpc: "2.0",
            id: "access-key-list",
            method: "query",
            params: QueryAccessKeyListParams {
                request_type: "view_access_key_list",
                finality: "final",
                account_id: &account_id,
            },
        },
    )?;

    let native_balance_yocto_near = account
        .result
        .amount
        .parse::<u128>()
        .map_err(|error| format!("failed to parse native account balance: {error}"))?;

    let keys = access_keys
        .result
        .keys
        .into_iter()
        .map(|key| ViewAccountKeyRow {
            public_key: key.public_key,
            nonce: key.access_key.nonce,
            permission_label: match key.access_key.permission {
                PermissionView::FullAccess => "full access".to_owned(),
                PermissionView::FunctionCall { .. } => "function call".to_owned(),
            },
        })
        .collect();

    Ok(ViewAccountData {
        account_id,
        native_balance_yocto_near,
        keys,
    })
}

async fn fetch_all_account_keys(
    network: Network,
    provider: ProviderKind,
    account_ids: Vec<String>,
) -> Result<LoadedAccountDirectory, String> {
    if account_ids.is_empty() {
        return Err("there are no saved accounts to refresh".to_owned());
    }

    let mut accounts = BTreeMap::new();
    let mut key_count = 0;

    for account_id in account_ids {
        let loaded = fetch_account_keys(network, provider, account_id).await?;
        key_count += loaded.rows.len();
        accounts.insert(loaded.account_id, loaded.rows);
    }

    Ok(LoadedAccountDirectory {
        network,
        accounts,
        key_count,
    })
}

fn save_account_keys(
    db: &sled::Db,
    account_directory: &mut BTreeMap<String, Vec<AccountAccessKeyRow>>,
    loaded: LoadedAccountKeys,
) -> Result<(), String> {
    let mut rows = account_directory.remove(&loaded.account_id).unwrap_or_default();
    rows.retain(|entry| entry.network != loaded.network);
    rows.extend(loaded.rows);
    account_directory.insert(loaded.account_id, rows);
    let bytes = serde_json::to_vec(account_directory)
        .map_err(|error| format!("failed to encode saved account keys: {error}"))?;
    db.insert(SAVED_ACCOUNT_KEYS_DB_KEY, bytes)
        .map_err(|error| format!("failed to store saved account keys: {error}"))?;
    db.flush()
        .map_err(|error| format!("failed to flush saved account keys: {error}"))?;
    Ok(())
}

fn replace_saved_account_keys(
    db: &sled::Db,
    account_directory: &mut BTreeMap<String, Vec<AccountAccessKeyRow>>,
    loaded: LoadedAccountDirectory,
) -> Result<(), String> {
    let mut merged = account_directory.clone();
    for (account_id, fresh_rows) in loaded.accounts {
        let mut rows = merged.remove(&account_id).unwrap_or_default();
        rows.retain(|entry| entry.network != loaded.network);
        rows.extend(fresh_rows);
        merged.insert(account_id, rows);
    }
    let bytes = serde_json::to_vec(&merged).map_err(|error| format!("failed to encode saved account keys: {error}"))?;
    db.insert(SAVED_ACCOUNT_KEYS_DB_KEY, bytes)
        .map_err(|error| format!("failed to store saved account keys: {error}"))?;
    db.flush()
        .map_err(|error| format!("failed to flush saved account keys: {error}"))?;
    *account_directory = merged;
    Ok(())
}

fn load_saved_account_keys(db: &sled::Db) -> Result<BTreeMap<String, Vec<AccountAccessKeyRow>>, String> {
    match db
        .get(SAVED_ACCOUNT_KEYS_DB_KEY)
        .map_err(|error| format!("failed to read saved account keys: {error}"))?
    {
        Some(bytes) => {
            serde_json::from_slice(&bytes).map_err(|error| format!("failed to decode saved account keys: {error}"))
        }
        None => Ok(BTreeMap::new()),
    }
}

fn default_account_network() -> Network {
    Network::Mainnet
}

fn default_public_key_for_network(
    account_directory: &BTreeMap<String, Vec<AccountAccessKeyRow>>,
    account_id: &str,
    network: Network,
) -> String {
    let matching_keys: Vec<&AccountAccessKeyRow> = account_directory
        .get(account_id)
        .map(|keys| keys.iter().filter(|entry| entry.network == network).collect())
        .unwrap_or_default();

    if matching_keys.len() == 1 {
        matching_keys[0].public_key.clone()
    } else {
        String::new()
    }
}

fn clear_saved_account_keys(
    db: &sled::Db,
    account_directory: &mut BTreeMap<String, Vec<AccountAccessKeyRow>>,
) -> Result<(), String> {
    account_directory.clear();
    db.insert(SAVED_ACCOUNT_KEYS_DB_KEY, b"{}".as_slice())
        .map_err(|error| format!("failed to clear saved account keys: {error}"))?;
    db.flush()
        .map_err(|error| format!("failed to flush cleared account keys: {error}"))?;
    Ok(())
}

fn delete_saved_account_key(
    db: &sled::Db,
    account_directory: &mut BTreeMap<String, Vec<AccountAccessKeyRow>>,
    account_id: &str,
    network: Network,
    public_key: &str,
) -> Result<(), String> {
    if let Some(rows) = account_directory.get_mut(account_id) {
        rows.retain(|entry| !(entry.network == network && entry.public_key == public_key));
        if rows.is_empty() {
            account_directory.remove(account_id);
        }
    }

    let bytes = serde_json::to_vec(account_directory)
        .map_err(|error| format!("failed to encode saved account keys: {error}"))?;
    db.insert(SAVED_ACCOUNT_KEYS_DB_KEY, bytes)
        .map_err(|error| format!("failed to store saved account keys: {error}"))?;
    db.flush()
        .map_err(|error| format!("failed to flush saved account keys: {error}"))?;
    Ok(())
}

fn rpc_endpoint(network: Network, provider: ProviderKind) -> String {
    let rpc = JsonRpc::new(network, provider);
    rpc.rpc_url().to_owned()
}

fn rpc_name(network: Network, provider: ProviderKind) -> String {
    JsonRpc::new(network, provider).config_key().to_owned()
}

fn default_signed_response_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join(".airgap")
        .join("airgap-offline")
        .join("out")
        .join("transaction-signed.json")
        .display()
        .to_string()
}

fn post_rpc<T, P>(
    client: &reqwest::blocking::Client,
    rpc_name: &str,
    endpoint: &str,
    request: RpcRequest<'_, P>,
) -> Result<RpcResponse<T>, String>
where
    T: for<'de> Deserialize<'de>,
    P: Serialize,
{
    tracing::info!(
        provider = rpc_name,
        method = request.method,
        endpoint = endpoint,
        "rpc request"
    );

    let response = client
        .post(endpoint)
        .json(&request)
        .send()
        .map_err(|error| format!("{rpc_name} RPC request failed: {error}"))?;

    let status = response.status();
    let body = response
        .text()
        .map_err(|error| format!("failed to read {rpc_name} RPC response: {error}"))?;

    if !status.is_success() {
        return Err(format!("{rpc_name} RPC returned HTTP {status}: {body}"));
    }

    let envelope: RpcEnvelope = serde_json::from_str(&body)
        .map_err(|error| format!("failed to decode {rpc_name} RPC response: {error}: {body}"))?;

    if let Some(error) = envelope.error {
        return Err(format!("{rpc_name} RPC error {}: {}", error.code, error.message));
    }

    let result = envelope
        .result
        .ok_or_else(|| format!("{rpc_name} RPC response did not include result: {body}"))?;

    if let Some(error) = result.get("error").and_then(serde_json::Value::as_str) {
        return Err(format!("{rpc_name} RPC error: {error}"));
    }

    let result = serde_json::from_value(result)
        .map_err(|error| format!("failed to decode {rpc_name} RPC result: {error}: {body}"))?;

    Ok(RpcResponse { result })
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a, P> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: P,
}

#[derive(Debug, Serialize)]
struct QueryAccessKeyParams<'a> {
    request_type: &'a str,
    finality: &'a str,
    account_id: &'a str,
    public_key: &'a str,
}

#[derive(Debug, Serialize)]
struct QueryAccessKeyListParams<'a> {
    request_type: &'a str,
    finality: &'a str,
    account_id: &'a str,
}

#[derive(Debug, Serialize)]
struct QueryViewAccountParams<'a> {
    request_type: &'a str,
    finality: &'a str,
    account_id: &'a str,
}

#[derive(Debug, Serialize)]
struct BlockParams<'a> {
    finality: &'a str,
}

#[derive(Debug, Serialize)]
struct BroadcastTxParams<'a> {
    signed_tx_base64: &'a str,
    wait_until: &'a str,
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: T,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ViewAccessKeyResult {
    nonce: u64,
}

#[derive(Debug, Deserialize)]
struct ViewAccessKeyListResult {
    keys: Vec<AccessKeyListItem>,
}

#[derive(Debug, Deserialize)]
struct AccessKeyListItem {
    public_key: String,
    access_key: AccessKeyView,
}

#[derive(Debug, Deserialize)]
struct AccessKeyView {
    nonce: u64,
    permission: PermissionView,
}

#[derive(Debug, Deserialize)]
struct ViewAccountResult {
    amount: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
enum PermissionView {
    FullAccess,
    FunctionCall {
        allowance: Option<String>,
        receiver_id: String,
        method_names: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
struct BlockResult {
    header: BlockHeader,
}

#[derive(Debug, Deserialize)]
struct BlockHeader {
    hash: String,
}
