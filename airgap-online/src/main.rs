use airgap_core::{NearNetwork, SignedTransactionResponse, TransferDraft, request_to_pretty_json, response_from_json};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use borsh::from_slice;
use iced::{
    Alignment, Border, Color, Element, Length, Task, alignment, clipboard,
    widget::{button, column, container, pane_grid, pick_list, row, scrollable, text, text_input},
};
use near_primitives::transaction::{Action, SignedTransaction, Transaction};
use near_primitives::types::Balance;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::PathBuf};
const SIDEBAR_RATIO: f32 = 0.24;
const NETWORK_COLUMN_WIDTH: f32 = 120.0;
const PERMISSION_COLUMN_WIDTH: f32 = 140.0;
const ACCOUNT_COLUMN_WIDTH: f32 = 220.0;
const SAVED_ACCOUNT_KEYS_DB_KEY: &[u8] = b"saved_account_keys";

fn main() -> iced::Result {
    iced::application(OnlineApp::default, OnlineApp::update, OnlineApp::view)
        .title("🌐 Airgap Online")
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
    output_dir().join("unsigned-transfer.json").display().to_string()
}

#[derive(Debug, Clone)]
enum Message {
    SplitResized(pane_grid::ResizeEvent),
    TabSelected(Tab),
    NetworkChanged(NearNetwork),
    SignerIdChanged(String),
    SignerKnownAccountSelected(String),
    SignerPublicKeyChanged(String),
    SignerKnownPublicKeySelected(String),
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
    RefreshAccountKeysPressed,
    CleanupAccountKeysPressed,
    AccountKeysFetched(Result<LoadedAccountKeys, String>),
    AccountDirectoryRefreshed(Result<LoadedAccountDirectory, String>),
    CopyGeneratedPathPressed(String),
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
    layout: pane_grid::State<LayoutPane>,
    active_tab: Tab,
    network: NearNetwork,
    signer_id: String,
    signer_public_key: String,
    receiver_id: String,
    nonce: String,
    block_hash: String,
    deposit_near: String,
    output: String,
    status: Status,
    last_generated: Option<RequestSnapshot>,
    account_lookup: String,
    account_directory: BTreeMap<String, Vec<AccountAccessKeyRow>>,
    account_status: AccountStatus,
    signed_response_path: String,
    broadcast_state: BroadcastState,
}

#[derive(Debug, Clone, Copy)]
enum LayoutPane {
    Sidebar,
    Main,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Sign,
    Broadcast,
    Accounts,
}

impl Default for OnlineApp {
    fn default() -> Self {
        let db = sled::open(db_path()).expect("failed to open online account database");
        let account_directory = load_saved_account_keys(&db).unwrap_or_default();

        Self {
            db,
            layout: build_split_layout(),
            active_tab: Tab::Sign,
            network: NearNetwork::Mainnet,
            signer_id: String::new(),
            signer_public_key: String::new(),
            receiver_id: String::new(),
            nonce: String::new(),
            block_hash: String::new(),
            deposit_near: String::new(),
            output: default_output_path(),
            status: Status::Idle,
            last_generated: None,
            account_lookup: String::new(),
            account_directory,
            account_status: AccountStatus::Idle,
            signed_response_path: default_signed_response_path(),
            broadcast_state: BroadcastState::Idle,
        }
    }
}

impl OnlineApp {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SplitResized(event) => {
                self.layout.resize(event.split, event.ratio);
            }
            Message::TabSelected(tab) => {
                self.active_tab = tab;
            }
            Message::NetworkChanged(network) => {
                self.network = network;
                self.signer_public_key =
                    default_public_key_for_network(&self.account_directory, self.signer_id.trim(), network);
                self.mark_dirty();
            }
            Message::SignerIdChanged(value) => {
                self.signer_id = value;
                self.mark_dirty();
            }
            Message::SignerKnownAccountSelected(account_id) => {
                self.signer_id = account_id.clone();
                self.signer_public_key =
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
                self.account_status = AccountStatus::Fetching;
                return Task::perform(fetch_account_keys(network, account_id), Message::AccountKeysFetched);
            }
            Message::RefreshAccountKeysPressed => {
                let network = self.network;
                let account_ids = self
                    .account_directory
                    .iter()
                    .filter(|(_, rows)| rows.iter().any(|entry| entry.network == network))
                    .map(|(account_id, _)| account_id.clone())
                    .collect();
                self.account_status = AccountStatus::Fetching;
                return Task::perform(
                    fetch_all_account_keys(network, account_ids),
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
            Message::CopyGeneratedPathPressed(path) => {
                return clipboard::write(path);
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
                    broadcast_signed_transaction(self.network, loaded),
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
        pane_grid(&self.layout, |_, pane, _| match pane {
            LayoutPane::Sidebar => pane_grid::Content::new(online_sidebar_view(self.active_tab)),
            LayoutPane::Main => pane_grid::Content::new(online_main_view(self)),
        })
        .width(Length::Fill)
        .height(Length::Fill)
        .spacing(1)
        .on_resize(8, Message::SplitResized)
        .into()
    }

    fn generate_request(&self) -> Result<GeneratedRequest, String> {
        let nonce = parse_u64("nonce", &self.nonce)?;
        let deposit = parse_near_amount(&self.deposit_near)?;
        let output = parse_output_path(&self.output)?;

        let request = TransferDraft {
            network: self.network,
            signer_id: self.signer_id.trim().to_owned(),
            signer_public_key: self.signer_public_key.trim().to_owned(),
            receiver_id: self.receiver_id.trim().to_owned(),
            nonce,
            block_hash: self.block_hash.trim().to_owned(),
            deposit_yocto_near: deposit,
        }
        .into_request()
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
            network: self.network,
            signer_id: self.signer_id.trim().to_owned(),
            signer_public_key: self.signer_public_key.trim().to_owned(),
            receiver_id: self.receiver_id.trim().to_owned(),
            nonce: self.nonce.trim().to_owned(),
            block_hash: self.block_hash.trim().to_owned(),
            deposit_near: self.deposit_near.trim().to_owned(),
            output: self.output.trim().to_owned(),
        }
    }
}

fn online_sidebar_view<'a>(active_tab: Tab) -> Element<'a, Message> {
    container(
        column![
            text("🌐 Airgap Online").size(24),
            text("Hot machine").size(14),
            online_tab_button("Sign", Tab::Sign, active_tab),
            online_tab_button("Broadcast", Tab::Broadcast, active_tab),
            online_tab_button("Accounts", Tab::Accounts, active_tab),
        ]
        .spacing(16)
        .padding(20)
        .align_x(Alignment::Start),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn online_main_view(app: &OnlineApp) -> Element<'_, Message> {
    match app.active_tab {
        Tab::Sign => online_sign_view(app),
        Tab::Broadcast => online_broadcast_view(app),
        Tab::Accounts => online_accounts_view(app),
    }
}

fn online_broadcast_view(app: &OnlineApp) -> Element<'_, Message> {
    let network = column![
        text("Network").size(14),
        pick_list(
            [NearNetwork::Testnet, NearNetwork::Mainnet],
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
            button(text("Broadcast Transaction").size(16))
                .padding([12, 18])
                .on_press(Message::BroadcastSignedTransactionPressed),
        );
    }

    scrollable(
        container(
            column![
                text("Broadcast").size(32),
                text("Load a signed response file from the offline machine and send it to NEAR RPC.").size(16),
                network,
                response_input,
                broadcast_state_view(&app.broadcast_state),
                actions,
            ]
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
            [NearNetwork::Testnet, NearNetwork::Mainnet],
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
            button(text("Fetch from Lava RPC").size(16))
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
        chain_state,
        field("Deposit in NEAR", &app.deposit_near, Message::DepositChanged),
        field("Output file", &app.output, Message::OutputChanged),
    ]
    .spacing(16)
    .width(Length::Fill);

    let mut generate_button = button(text("Generate request").size(16)).padding([12, 18]);
    if app.can_generate() {
        generate_button = generate_button.on_press(Message::GeneratePressed);
    }

    let actions = column![
        row![generate_button].spacing(16).align_y(Alignment::Center),
        status_view(&app.status),
    ]
    .spacing(12)
    .width(Length::Fill);

    scrollable(
        container(
            column![
                text("🌐 Airgap Online").size(32),
                text("Create a NEAR transfer request for offline signing.").size(16),
                form,
                actions,
            ]
            .spacing(28)
            .padding(28)
            .width(Length::Fill),
        )
        .width(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn online_accounts_view(app: &OnlineApp) -> Element<'_, Message> {
    let network = column![
        text("Network").size(14),
        pick_list(
            [NearNetwork::Testnet, NearNetwork::Mainnet],
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

    scrollable(
        container(
            column![
                text("Accounts").size(32),
                text("Preset account ids and load every access key from Lava RPC. One account can have multiple keys.")
                    .size(16),
                network,
                column![text("Account").size(14), lookup].spacing(8),
                account_status_view(&app.account_status),
                table,
                table_actions,
            ]
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

fn build_split_layout() -> pane_grid::State<LayoutPane> {
    let (mut layout, sidebar) = pane_grid::State::new(LayoutPane::Sidebar);
    if let Some((main, split)) = layout.split(pane_grid::Axis::Vertical, sidebar, LayoutPane::Main) {
        let _ = main;
        layout.resize(split, SIDEBAR_RATIO);
    }
    layout
}

fn online_tab_button<'a>(label: &'static str, tab: Tab, active_tab: Tab) -> Element<'a, Message> {
    let mut tab_button = button(text(label).size(15)).padding([10, 18]).width(Length::Fill);
    if tab != active_tab {
        tab_button = tab_button.on_press(Message::TabSelected(tab));
    }
    tab_button.into()
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
    ]
    .spacing(16)
    .align_y(Alignment::Center);

    let rows = account_directory
        .iter()
        .flat_map(|(account_id, keys)| {
            keys.iter().map(move |entry| {
                column![
                    row![
                        container(text(account_id.as_str()).size(14)).width(Length::Fixed(ACCOUNT_COLUMN_WIDTH)),
                        container(text(entry.network.to_string()).size(14)).width(Length::Fixed(NETWORK_COLUMN_WIDTH)),
                        container(text(entry.permission_label.as_str()).size(14))
                            .width(Length::Fixed(PERMISSION_COLUMN_WIDTH)),
                        container(text(entry.public_key.as_str()).size(14)).width(Length::Fill),
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
        AccountStatus::Idle => text("Load an account to inspect all access keys from Lava RPC.")
            .size(15)
            .into(),
        AccountStatus::Fetching => text("Loading account keys from Lava RPC...").size(15).into(),
        AccountStatus::Loaded { account_id, key_count } => {
            if *key_count == 0 {
                text(format!(
                    "Loaded 0 access key(s) for {account_id}. Check that the selected network matches this account."
                ))
                .size(15)
                .into()
            } else {
                text(format!("Loaded {key_count} access key(s) for {account_id}."))
                    .size(15)
                    .into()
            }
        }
        AccountStatus::Refreshed {
            account_count,
            key_count,
        } => text(format!(
            "Refreshed {account_count} saved account(s) and loaded {key_count} access key(s) from Lava RPC."
        ))
        .size(15)
        .into(),
        AccountStatus::Error(error) => text(format!("Error: {error}"))
            .size(15)
            .align_x(alignment::Horizontal::Center)
            .into(),
    }
}

fn status_view(status: &Status) -> Element<'_, Message> {
    match status {
        Status::Idle | Status::Fetching | Status::Fetched(_) => text("Ready").size(15).into(),
        Status::Success(result) => {
            let absolute_path = result.output.display().to_string();

            column![
                text("Request file created").size(15),
                text(format!("id: {}", result.id)).size(13),
                row![
                    text(format!("path: {absolute_path}")).size(13),
                    button(text("Copy Path").size(13))
                        .padding([6, 10])
                        .on_press(Message::CopyGeneratedPathPressed(absolute_path)),
                ]
                .spacing(12)
                .align_y(Alignment::Center),
                text("Edit any field to generate again.").size(13),
            ]
            .spacing(4)
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
            text("Loaded from Lava RPC").size(15),
            text(format!("next nonce: {}", chain_state.next_nonce)).size(13),
            text(format!("block hash: {}", chain_state.block_hash)).size(13),
        ]
        .spacing(4)
        .into(),
        Status::Error(error) => text(format!("Error: {error}"))
            .size(15)
            .align_x(alignment::Horizontal::Center)
            .into(),
        Status::Idle | Status::Success(_) => text("Nonce and block hash can be fetched from Lava RPC.")
            .size(15)
            .into(),
    }
}

fn broadcast_state_view(state: &BroadcastState) -> Element<'_, Message> {
    let content: Element<'_, Message> = match state {
        BroadcastState::Idle => text("Load a signed response file to inspect and broadcast it.")
            .size(15)
            .into(),
        BroadcastState::Loading => text("Loading signed response...").size(15).into(),
        BroadcastState::Loaded(loaded) => column![
            text("Signed transaction loaded").size(15),
            text(format!("request id: {}", loaded.request_id)).size(13),
            text(format!("transaction hash: {}", loaded.transaction_hash)).size(13),
            text(format!("signer: {}", loaded.signer_id)).size(13),
            text(format!("receiver: {}", loaded.receiver_id)).size(13),
            text(format!(
                "deposit: {} NEAR",
                format_yocto_near(loaded.deposit_yocto_near)
            ))
            .size(13),
            text(format!("nonce: {}", loaded.nonce)).size(13),
            text(format!("public key: {}", loaded.public_key)).size(13),
            text(format!("signature: {}", loaded.signature)).size(13),
        ]
        .spacing(4)
        .into(),
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
    network: NearNetwork,
    signer_id: String,
    signer_public_key: String,
    receiver_id: String,
    nonce: String,
    block_hash: String,
    deposit_near: String,
    output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountAccessKeyRow {
    #[serde(default = "default_account_network")]
    network: NearNetwork,
    public_key: String,
    permission_label: String,
}

#[derive(Debug, Clone)]
struct LoadedAccountKeys {
    network: NearNetwork,
    account_id: String,
    rows: Vec<AccountAccessKeyRow>,
}

#[derive(Debug, Clone)]
struct LoadedAccountDirectory {
    network: NearNetwork,
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
    receiver_id: String,
    nonce: u64,
    deposit_yocto_near: u128,
    public_key: String,
    signature: String,
    signed_tx_base64: String,
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

async fn fetch_chain_state(network: NearNetwork, account_id: String, public_key: String) -> Result<ChainState, String> {
    if account_id.is_empty() {
        return Err("signer account is required before fetching chain state".to_owned());
    }

    if public_key.is_empty() {
        return Err("signer public key is required before fetching chain state".to_owned());
    }

    let endpoint = lava_rpc_endpoint(network);
    let client = reqwest::blocking::Client::new();

    let access_key: RpcResponse<ViewAccessKeyResult> = post_rpc(
        &client,
        endpoint,
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
        endpoint,
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
    let [Action::Transfer(transfer)] = transaction.actions.as_slice() else {
        return Err("only single-action transfer transactions are supported".to_owned());
    };

    Ok(LoadedSignedResponse {
        request_id: response.request_id,
        transaction_hash: signed_tx.get_hash().to_string(),
        signer_id: transaction.signer_id.to_string(),
        receiver_id: transaction.receiver_id.to_string(),
        nonce: transaction.nonce,
        deposit_yocto_near: transfer.deposit.as_yoctonear(),
        public_key: response.public_key,
        signature: response.signature,
        signed_tx_base64: response.signed_transaction_borsh_base64,
    })
}

async fn broadcast_signed_transaction(
    network: NearNetwork,
    loaded: LoadedSignedResponse,
) -> Result<BroadcastResult, String> {
    let endpoint = lava_rpc_endpoint(network);
    let client = reqwest::blocking::Client::new();

    let result: Value = post_rpc(
        &client,
        endpoint,
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

async fn fetch_account_keys(network: NearNetwork, account_id: String) -> Result<LoadedAccountKeys, String> {
    let account_id = account_id.trim().to_owned();
    if account_id.is_empty() {
        return Err("account is required before loading keys".to_owned());
    }

    let endpoint = lava_rpc_endpoint(network);
    let client = reqwest::blocking::Client::new();

    let access_keys: RpcResponse<ViewAccessKeyListResult> = post_rpc(
        &client,
        endpoint,
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

async fn fetch_all_account_keys(
    network: NearNetwork,
    account_ids: Vec<String>,
) -> Result<LoadedAccountDirectory, String> {
    if account_ids.is_empty() {
        return Err("there are no saved accounts to refresh".to_owned());
    }

    let mut accounts = BTreeMap::new();
    let mut key_count = 0;

    for account_id in account_ids {
        let loaded = fetch_account_keys(network, account_id).await?;
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

fn default_account_network() -> NearNetwork {
    NearNetwork::Mainnet
}

fn default_public_key_for_network(
    account_directory: &BTreeMap<String, Vec<AccountAccessKeyRow>>,
    account_id: &str,
    network: NearNetwork,
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

fn lava_rpc_endpoint(network: NearNetwork) -> &'static str {
    match network {
        NearNetwork::Mainnet => "https://near.lava.build",
        NearNetwork::Testnet => "https://neart.lava.build",
    }
}

fn default_signed_response_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join(".airgap")
        .join("airgap-offline")
        .join("out")
        .join("signed-response.json")
        .display()
        .to_string()
}

fn post_rpc<T, P>(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    request: RpcRequest<'_, P>,
) -> Result<RpcResponse<T>, String>
where
    T: for<'de> Deserialize<'de>,
    P: Serialize,
{
    let response = client
        .post(endpoint)
        .json(&request)
        .send()
        .map_err(|error| format!("Lava RPC request failed: {error}"))?;

    let status = response.status();
    let body = response
        .text()
        .map_err(|error| format!("failed to read Lava RPC response: {error}"))?;

    if !status.is_success() {
        return Err(format!("Lava RPC returned HTTP {status}: {body}"));
    }

    let envelope: RpcEnvelope =
        serde_json::from_str(&body).map_err(|error| format!("failed to decode Lava RPC response: {error}: {body}"))?;

    if let Some(error) = envelope.error {
        return Err(format!("Lava RPC error {}: {}", error.code, error.message));
    }

    let result = envelope
        .result
        .ok_or_else(|| format!("Lava RPC response did not include result: {body}"))?;

    if let Some(error) = result.get("error").and_then(serde_json::Value::as_str) {
        return Err(format!("Lava RPC error: {error}"));
    }

    let result =
        serde_json::from_value(result).map_err(|error| format!("failed to decode Lava RPC result: {error}: {body}"))?;

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
    permission: PermissionView,
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
