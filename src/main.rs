use anyhow::Result;
use codec::Encode;
use log::{error, info, warn};
use paste::paste;
use reqwest::Client;
use serde_json::json;
use sp_consensus_babe::{BabeAuthorityWeight, Randomness};
use sp_core::U256;
use std::env;
use structopt::StructOpt;
use subxt::{utils::H256, OnlineClient};

mod metadata;
mod utils;
use metadata::{
    api,
    api::runtime_types::{
        pallet_identity::types::Data, sp_consensus_babe::app::Public, sp_consensus_slots::Slot,
        sp_core::crypto::KeyTypeId,
    },
};

pub const BABE: KeyTypeId = KeyTypeId(*b"babe");
pub const DEFAULT_CHANNEL_ID: &str = "channel-id";

use std::{collections::HashMap, fs};

fn load_local_map() -> HashMap<String, String> {
    if let Ok(content) = fs::read_to_string("offchain_identities.json") {
        // { "stash_account": "Validator Name", ... }
        if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&content) {
            return map;
        }
    }

    HashMap::new()
}

#[derive(StructOpt, Clone)]
struct Args {
    /// WebSocket URL
    #[structopt(short, long, default_value = "ws://127.0.0.1:9944")]
    ws: String,

    /// Slack channel ID
    #[structopt(short, long, default_value = DEFAULT_CHANNEL_ID)]
    channel_id: String,

    /// Enable posting to Slack
    #[structopt(long)]
    enable_slack: bool,
}

/// Track secondary slot authors
pub async fn track_secondary_authors() -> Result<()> {
    let args = Args::from_args();
    let client = OnlineClient::<utils::AvailConfig>::from_url(args.ws.clone()).await?;

    info!("Connection established to {}", args.ws);
    // Maybe listen to only finalised blocks
    let mut block_sub = client.blocks().subscribe_best().await?;

    let mut last_slot = None;

    while let Some(block) = block_sub.next().await {
        let block_hash = block?.hash();
        // Process block slot
        process_block_slots(&client, block_hash, &mut last_slot, args.clone()).await?;
    }

    Ok(())
}

/// Process a block and compare its slot with the last known slot to find missing slots.
async fn process_block_slots(
    client: &OnlineClient<utils::AvailConfig>,
    block_hash: H256,
    last_slot: &mut Option<Slot>,
    args: Args,
) -> Result<()> {
    // Fetch the current slot for the finalized block
    let current_slot = client
        .storage()
        .at(block_hash)
        .fetch(&api::storage().babe().current_slot())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to fetch current slot"))?;

    if let Some(last) = last_slot {
        // Compare current slot with the last known slot to find any missing slots
        if current_slot.0 > last.0 + 1 {
            warn!(
                "Missing slots detected between {} and {}",
                last.0, current_slot.0
            );
            find_missing_secondary_authors(last.0, current_slot.0, client, block_hash, &args)
                .await?;
        }
    }

    // Update the last_slot with the current slot
    *last_slot = Some(current_slot);

    Ok(())
}

/// Find secondary authors for any missing slots between two given slots.
async fn find_missing_secondary_authors(
    start_slot: u64,
    end_slot: u64,
    client: &OnlineClient<utils::AvailConfig>,
    block_hash: H256,
    args: &Args,
) -> Result<()> {
    // Fetch the validator authorities
    let authorities = client
        .storage()
        .at(block_hash)
        .fetch(&api::storage().babe().authorities())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to fetch authorities"))?
        .0;

    // Fetch the randomness
    let randomness = client
        .storage()
        .at(block_hash)
        .fetch(&api::storage().babe().randomness())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to fetch randomness"))?;

    // Find secondary authors for each missing slot
    let index = start_slot + 1;
    for slot in index..end_slot {
        let slot_author_index = secondary_slot_author(Slot(slot), &authorities, randomness);

        let owner = match get_key_owner(client, block_hash, slot_author_index as usize).await {
            Ok(owner) => owner,
            Err(e) => {
                // This should never happen, but better be cautious than sorry
                error!(
                    "Failed to get the owner for an auth_index {slot_author_index}: {}",
                    e
                );
                "UNKNOWN_OWNER".to_owned()
            }
        };

        let msg = format!(
            "Validator {} missed authoring secondary block for slot {}, detected at blockHash: {:#?}",
            owner, slot, block_hash
        );

        if args.enable_slack {
            info!("Slack notification is enabled");
            post_to_slack(&msg, &args.channel_id).await?;
        }

        info!("{}", msg);
    }

    Ok(())
}

macro_rules! match_raw_variants {
    ($data:expr, $($n:literal),*) => {
        paste! {
            match $data {
                $(
                    Data::[<Raw $n>](arr) => Some(String::from_utf8_lossy(arr).to_string()),
                )*
                _ => None,
            }
        }
    };
}

fn extract_raw_data(data: &Data) -> Option<String> {
    match_raw_variants!(
        data, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32
    )
}

/// Get the expected secondary author for the given slot and authorities.
fn secondary_slot_author(
    slot: Slot,
    authorities: &[(Public, BabeAuthorityWeight)],
    randomness: Randomness,
) -> u32 {
    let rand = U256::from((randomness, slot).using_encoded(sp_crypto_hashing::blake2_256));
    let authorities_len = U256::from(authorities.len());
    (rand % authorities_len).as_u32()
}

/// Get the key owner account for the given authority index.
async fn get_key_owner(
    client: &OnlineClient<utils::AvailConfig>,
    block_hash: H256,
    auth_index: usize,
) -> Result<String> {
    // Get the list of validators (stash accounts)
    let validators = client
        .storage()
        .at(block_hash)
        .fetch(&api::storage().session().validators())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to fetch validators"))?;

    let validator = validators
        .get(auth_index)
        .ok_or_else(|| anyhow::anyhow!("Invalid authority index"))?;

    // Try to fetch on-chain identity from IdentityOf
    let identity_opt = client
        .storage()
        .at(block_hash)
        .fetch(&api::storage().identity().identity_of(validator.clone()))
        .await?;

    if let Some((registration, _)) = identity_opt {
        if let Some(display) = extract_raw_data(&registration.info.display) {
            return Ok(format!("{} [{}]", display, validator));
        } else {
            return Ok(format!("NO_DISPLAY [{}]", validator));
        }
    }
    let local_map = load_local_map();
    if let Some(local_name) = local_map.get(&validator.to_string()) {
        return Ok(format!("{} [{}]", local_name, validator));
    }

    Ok(format!("NO_IDENT [{}]", validator))
}

async fn post_to_slack(message: &str, channel_id: &str) -> Result<()> {
    let slack_token = env::var("SLACK_TOKEN").unwrap_or_else(|_| "MAYBE_DEFAULT".to_string());

    let client = Client::new();

    // Define the payload for the API request
    let payload = json!({
        "channel": channel_id,
        "text": message,
    });

    // Send the POST request to Slack Web API
    let response = client
        .post("https://slack.com/api/chat.postMessage")
        .bearer_auth(slack_token)
        .json(&payload)
        .send()
        .await?;

    let status = response.status();
    if status.is_success() {
        info!("Message posted successfully!");
    } else {
        let body = response.text().await?;
        error!(
            "Failed to post message. Status: {:?}, Body: {}",
            status, body
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    track_secondary_authors().await?;
    Ok(())
}
