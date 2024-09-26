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
