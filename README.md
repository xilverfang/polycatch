# Polywatch

A high-performance Golang bot that detects "insider" trading signals on Polymarket by monitoring high-value USDC.e deposits into Polymarket proxy wallets and automatically copying trades.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Installing Go](#installing-go)
    - [Windows](#windows)
    - [Linux](#linux)
    - [macOS](#macos)
- [Getting Started](#getting-started)
  - [Clone the Repository](#clone-the-repository)
  - [Install Dependencies](#install-dependencies)
  - [Create API Credentials](#create-api-credentials)
  - [Configuration](#configuration)
- [Usage](#usage)
  - [Creating API Credentials](#creating-api-credentials)
  - [Running the Monitor](#running-the-monitor)
  - [Running the Executor](#running-the-executor)
  - [Running Both Together](#running-both-together)
- [Configuration Options](#configuration-options)
- [How It Works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Features

- **Real-time Monitoring**: Monitors Polygon blockchain for high-value USDC.e deposits to Polymarket proxy wallets
- **Insider Trade Detection**: Automatically detects trades placed after high-value deposits
- **Automatic Execution**: Copies insider trades with configurable amount
- **Slippage Protection**: Prevents execution if price moves beyond tolerance
- **Balance Management**: Interactive mode to specify trade amounts or auto-scaling
- **Inter-Process Communication**: Run monitor and executor in separate terminals via Unix sockets
- **L2 Authentication**: Secure API authentication using HMAC-SHA256

## Prerequisites

- Go 1.21 or higher
- A Polymarket account with:
  - Funder address (Polymarket proxy wallet)
  - Builder API credentials (API key, secret, passphrase)
  - Signer private key (MetaMask private key)
- Polygon WebSocket RPC endpoint (e.g., from Alchemy, Infura, or QuickNode)
- Minimum $1 USDC.e balance in your Polymarket funder address

## Installation

### Installing Go

#### Windows

1. **Download Go:**
   - Visit [https://go.dev/dl/](https://go.dev/dl/)
   - Download the Windows installer (e.g., `go1.21.x.windows-amd64.msi`)

2. **Run the Installer:**
   - Double-click the downloaded `.msi` file
   - Follow the installation wizard (defaults are fine)
   - Go will be installed to `C:\Program Files\Go`

3. **Verify Installation:**
   ```powershell
   go version
   ```
   You should see something like: `go version go1.21.x windows/amd64`

4. **Set Environment Variables (if needed):**
   - The installer usually sets these automatically
   - If `go` command is not found, add `C:\Program Files\Go\bin` to your PATH

#### Linux

1. **Download Go:**
   ```bash
   wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
   ```

2. **Remove Previous Installation (if any):**
   ```bash
   sudo rm -rf /usr/local/go
   ```

3. **Extract Archive:**
   ```bash
   sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
   ```

4. **Add to PATH:**
   Add the following to your `~/.bashrc` or `~/.zshrc`:
   ```bash
   export PATH=$PATH:/usr/local/go/bin
   ```

5. **Reload Shell Configuration:**
   ```bash
   source ~/.bashrc  # or source ~/.zshrc
   ```

6. **Verify Installation:**
   ```bash
   go version
   ```
   You should see: `go version go1.21.x linux/amd64`

#### macOS

1. **Using Homebrew (Recommended):**
   ```bash
   brew install go
   ```

2. **Or Download Manually:**
   - Visit [https://go.dev/dl/](https://go.dev/dl/)
   - Download the macOS package (e.g., `go1.21.x.darwin-amd64.pkg`)
   - Double-click to install

3. **Verify Installation:**
   ```bash
   go version
   ```
   You should see: `go version go1.21.x darwin/amd64`

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/yourusername/polywatch.git
cd polywatch
```

### Install Dependencies

```bash
go mod download
go mod tidy
```

Or use the Makefile:

```bash
make deps
```

### Create API Credentials

Before configuring the bot, you need Polymarket API credentials. You can create them programmatically using Polywatch:

1. **Set your signer private key** in `.env`:

```env
SIGNER_PRIVATE_KEY=0xYourPrivateKeyHere
```

2. **Build and run the API key creation command:**

```bash
make build
./polywatch --create-api-key
```

3. **Save the output credentials:**

The command will output your API credentials:

```
API Credentials:
  API Key:    550e8400-e29b-41d4-a716-446655440000
  Secret:     base64EncodedSecretString==
  Passphrase: randomPassphraseString
```

4. **Add these to your `.env` file:**

```env
BUILDER_API_KEY=550e8400-e29b-41d4-a716-446655440000
BUILDER_SECRET=base64EncodedSecretString==
BUILDER_PASSPHRASE=randomPassphraseString
```

**Note:** If you already have API credentials, this command will derive the existing ones rather than creating duplicates.

### Configuration

1. **Create a `.env` file** in the project root:

```bash
touch .env
```

2. **Add your configuration** to `.env`:

```env
# Required: Polygon WebSocket RPC URL
POLYGON_WSS_URL=wss://polygon-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_KEY

# Required: Your MetaMask private key (with 0x prefix)
SIGNER_PRIVATE_KEY=0xYourPrivateKeyHere

# Required: Your Polymarket funder address (from polymarket.com/settings)
FUNDER_ADDRESS=0xYourFunderAddressHere

# Required: Polymarket Builder API credentials (from Builder Dashboard)
BUILDER_API_KEY=your_api_key_here
BUILDER_SECRET=your_secret_here
BUILDER_PASSPHRASE=your_passphrase_here

# Optional: Minimum deposit amount to monitor (default: $10,000)
MIN_DEPOSIT_AMOUNT=10000

# Optional: Slippage tolerance percentage (default: 3%)
SLIPPAGE_TOLERANCE=3

# Optional: Interactive mode - prompt for trade amount (default: true)
INTERACTIVE_MODE=true

# Optional: Minimum trade amount in USD (default: $1)
MIN_TRADE_AMOUNT=1

# Optional: Max percentage of balance to use per trade (only if INTERACTIVE_MODE=false)
# Default: 100 (use all available balance)
MAX_TRADE_PERCENT=100
```

**Important Notes:**
- Never commit your `.env` file to version control
- The `.env` file is already in `.gitignore`
- Keep your private keys and API credentials secure

## Usage

### Building the Application

```bash
make build
```

Or manually:

```bash
go build -o polywatch ./cmd/polywatch
```

### Creating API Credentials

Generate or derive your Polymarket API credentials:

```bash
./polywatch --create-api-key
```

This uses L1 authentication to create or retrieve your API credentials. The credentials will be printed to the console - save them to your `.env` file.

### Running the Monitor

The monitor component listens for high-value deposits and detects insider trades:

```bash
./polywatch --monitor
```

Or if using `make`:

```bash
make build
./polywatch --monitor
```

**What it does:**
- Monitors Polygon blockchain for USDC.e transfers
- Detects high-value deposits to Polymarket proxy wallets
- Queries Polymarket Data API for new trades
- Sends trade signals via Unix socket (if executor is running separately)

### Running the Executor

The executor component receives trade signals and executes trades:

```bash
./polywatch --executor
```

**What it does:**
- Connects to monitor via Unix socket
- Receives trade signals in real-time
- Prompts for trade amount (if `INTERACTIVE_MODE=true`)
- Executes trades with slippage and balance checks

### Running Both Together

Run both monitor and executor in the same process:

```bash
./polywatch --monitor --executor
```

**Note:** When running together, signals are passed via in-process channels (faster than IPC).

### Running in Separate Terminals

For better control and monitoring, run them separately:

**Terminal 1 (Monitor):**
```bash
./polywatch --monitor
```

**Terminal 2 (Executor):**
```bash
./polywatch --executor
```

The executor will automatically connect to the monitor via Unix socket.

## Configuration Options

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `POLYGON_WSS_URL` | Polygon WebSocket RPC endpoint | `wss://polygon-mainnet.g.alchemy.com/v2/KEY` |
| `SIGNER_PRIVATE_KEY` | MetaMask private key (with 0x) | `0x1234...` |
| `FUNDER_ADDRESS` | Polymarket funder/proxy address | `0xabcd...` |
| `BUILDER_API_KEY` | Polymarket Builder API key | `550e8400-...` |
| `BUILDER_SECRET` | Polymarket Builder API secret | `base64...` |
| `BUILDER_PASSPHRASE` | Polymarket Builder API passphrase | `passphrase` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MIN_DEPOSIT_AMOUNT` | Minimum deposit to monitor (USD) | `10000` |
| `SLIPPAGE_TOLERANCE` | Maximum slippage percentage | `3` |
| `INTERACTIVE_MODE` | Prompt for trade amount | `true` |
| `MIN_TRADE_AMOUNT` | Minimum trade amount (USD) | `1` |
| `MAX_TRADE_PERCENT` | Max balance % per trade (auto-mode) | `100` |

## How It Works

### Architecture

1. **Listener (G1)**: Monitors Polygon blockchain for USDC.e transfers
2. **Analyst (G2)**: Detects trades placed after high-value deposits
3. **Executor (G3)**: Executes trades with user confirmation

### Flow

```
High-Value Deposit Detected
    ↓
Add Address to Watchlist
    ↓
Monitor for New Trades
    ↓
Trade Detected → Fetch Price from CLOB API
    ↓
Create Trade Signal
    ↓
Send to Executor (via IPC or channel)
    ↓
User Enters Trade Amount (Interactive Mode)
    ↓
Slippage Check → Balance Check
    ↓
Execute Trade
```

### Key Features

- **Baseline Snapshot**: Establishes baseline of existing positions to only alert on NEW trades
- **Price Accuracy**: Fetches current price from CLOB API for accurate execution
- **Slippage Protection**: Rejects trades if price moved >3% (configurable)
- **Balance Scaling**: Automatically scales trades to available balance (if not in interactive mode)

## Troubleshooting

### Common Issues

**1. "POLYGON_WSS_URL is required" error**
- Ensure your `.env` file exists and contains `POLYGON_WSS_URL`
- Check that the WebSocket URL is correct (must start with `wss://`)

**2. "Unauthorized/Invalid api key" error**
- Verify your Builder API credentials in `.env`
- Ensure no extra spaces or quotes around values
- Regenerate API credentials in Polymarket Builder Dashboard if needed

**3. "Connection refused" (IPC)**
- Ensure monitor is running before starting executor
- Check that socket file exists: `/tmp/polywatch-signals.sock`
- Try running both in the same process: `./polywatch --monitor --executor`

**4. "Insufficient balance" error**
- Ensure you have at least $3 USDC.e in your funder address
- Check balance on [Polygonscan](https://polygonscan.com)
- In interactive mode, enter an amount within your balance

**5. "Slippage exceeds tolerance"**
- Price moved too much between signal and execution
- Increase `SLIPPAGE_TOLERANCE` in `.env` (not recommended)
- This is a safety feature - the trade was likely not profitable

### Getting Help

- Check logs for detailed error messages
- Verify all configuration values are correct
- Ensure your Polymarket account is properly set up
- Check that you have sufficient balance

## Development

### Running Tests

```bash
make test
```

Or:

```bash
go test ./...
```

### Code Formatting

```bash
make fmt
```

Or:

```bash
go fmt ./...
```

### Building

```bash
make build
```

### Available Make Targets

```bash
make help
```

Common targets:
- `build` - Build the binary
- `test` - Run tests
- `fmt` - Format code
- `clean` - Remove build artifacts
- `deps` - Download and tidy dependencies

### Command-Line Flags

```bash
./polywatch [flags]
```

| Flag | Description |
|------|-------------|
| `--monitor` | Run the monitor (detects high-value deposits and trades) |
| `--executor` | Run the executor (executes trade signals) |
| `--create-api-key` | Create or derive Polymarket API credentials |

**Examples:**
```bash
./polywatch --monitor              # Monitor only
./polywatch --executor             # Executor only (connects via IPC)
./polywatch --monitor --executor   # Run both together
./polywatch --create-api-key       # Generate API credentials
```

### Project Structure

```
polywatch/
├── cmd/
│   └── polywatch/        # Main application entry point
├── internal/
│   ├── analyst/          # Trade detection and analysis
│   ├── config/           # Configuration management
│   ├── executor/         # Trade execution
│   ├── ipc/              # Inter-process communication
│   ├── listener/         # Blockchain event monitoring
│   ├── types/            # Data structures
│   └── utils/            # Utility functions
├── .env                  # Configuration file (create this)
├── go.mod               # Go module definition
├── Makefile             # Build automation
└── README.md            # This file
```

## Security Notes

- **Never share your private keys or API credentials**
- Keep your `.env` file secure and never commit it
- Use environment variables in production instead of `.env` files
- Regularly rotate your API credentials
- Monitor your account for unauthorized activity

## License

[MIT]

## Contributing


---

**Happy Trading! 🚀**

