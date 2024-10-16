use anyhow::Result;
use codec::Encode;
use log::{error, info, warn};
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
        sp_consensus_babe::app::Public, sp_consensus_slots::Slot, sp_core::crypto::KeyTypeId,
    },
};

pub const BABE: KeyTypeId = KeyTypeId(*b"babe");
pub const DEFAULT_CHANNEL_ID: &str = "channel-id";

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

        let author_key = &authorities
            .get(slot_author_index as usize)
            .ok_or_else(|| anyhow::anyhow!("Invalid authority index"))?
            .0
             .0;

        // Fetch the author account for this authority index
        let owner = client
            .storage()
            .at(block_hash)
            .fetch(
                &api::storage()
                    .session()
                    .key_owner(BABE, author_key.0.as_slice()),
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("Failed to fetch key owner for slot: {}", slot))?;

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
