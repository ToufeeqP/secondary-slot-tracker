# Secondary Slot Tracker

A simple tool to track the authorship of secondary slots in a Substrate-based blockchain network. It listens to the blocks, identifies any missing secondary slots, and determines the validator responsible for each missed slot. Additionally, it can optionally post notifications about missed slots to a Slack channel.

## Installation

Ensure you have Rust and Cargo installed. You can install Rust via [rustup](https://rustup.rs/).

Clone the repository:

```bash
git clone https://github.com/ToufeeqP/secondary-slot-tracker.git
cd secondary-slot-tracker
```

Build the project:

```bash
cargo build --release
```

## Usage

You can invoke the tool by running the following command:

```bash
./target/release/secondary-slot-tracker --ws <WebSocket URL> [options]
```

### Command-line Arguments

- `--ws`: The WebSocket URL for the Substrate node (default: `ws://127.0.0.1:9944`).
- `--channel-id`: The Slack channel ID to post notifications.
- `--enable-slack`: Enable posting to Slack if specified.

### Environment Variables

- `SLACK_TOKEN`: The Slack token used for authentication when posting notifications.

### Example

Run the tool with default settings:

```bash
./target/release/secondary-slot-tracker
```

Run the tool and enable Slack notifications:

```bash
./target/release/secondary-slot-tracker --enable-slack --channel-id C1234567890
```

## Logging

The tool uses the `log` crate to provide different levels of logging (info, warning, error). You can control the verbosity of the logs by setting the `RUST_LOG` environment variable.

Example:

```bash
RUST_LOG=info ./target/release/secondary-slot-tracker
```

To log all messages:

```bash
RUST_LOG=trace ./target/release/secondary-slot-tracker
```

## Slack Integration

To enable Slack integration, the tool posts notifications about missed secondary slots to a Slack channel.

- Set the `SLACK_TOKEN` environment variable with your Slack token.
- Use the `--channel-id` argument to specify the Slack channel.

Example:

```bash
export SLACK_TOKEN="your-slack-token"
./target/release/secondary-slot-tracker --enable-slack --channel-id C1234567890
```

## Tracker status

The tracker serves HTTP on `0.0.0.0:8080` by default. Override the bind address
with `--status-addr 127.0.0.1:8080` or `STATUS_ADDR`.

```bash
curl -i http://localhost:8080/health
```

The endpoint returns JSON, for example:

```json
{
  "status": "healthy",
  "last_tracked_block": {
    "number": 42,
    "hash": "0x...",
    "slot": 123,
    "tracked_at_unix_seconds": 1795560000,
    "seconds_since_last_block": 3
  }
}
```

`/health` returns HTTP 200 after a successfully processed
block, or 503 while starting or when no block has completed processing for 120
seconds (`status: "stale"`). Before the first block, `status` is `"starting"`
and `last_tracked_block` is `null`. Progress is held in memory and resets on restart.
Blocks are recorded only after slot processing and any enabled Slack notifications
complete. The tracker follows best blocks, so the reported block is not necessarily
finalized and its number can move backwards during a reorganization. Fatal tracker
or HTTP server errors stop the process; a stalled tracker continues serving its
last recorded progress with an unhealthy response.

The endpoint has no authentication; keep the port on a trusted network.
