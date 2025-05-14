# 🚩 WorldFlag Contracts

A decentralized, global capture-the-flag game powered by smart contracts and protected by World ID.

## Overview

WorldFlag is an innovative on-chain game where players compete to claim and hold a digital flag. The game implements sybil resistance through World ID integration, ensuring fair play and authentic participation.

### Key Features

- **Single Flag Holder**: Only one player can hold the flag at any given time
- **Sybil Protection**: Integration with World ID prevents multiple claims from the same person
- **Cooldown Period**: Players can only attempt to claim once per hour
- **Token Rewards**: Flag holders earn 1 $FLAG token per second while holding the flag
- **Upgradeable Design**: Implements the UUPS (Universal Upgradeable Proxy Standard) pattern from OpenZeppelin

## Technical Architecture

The contracts use the UUPS upgradeability proxy pattern from OpenZeppelin, allowing for future improvements while maintaining state. This architecture consists of:

- Proxy contract that holds the state
- Implementation contract that holds the logic
- Transparent upgrade mechanism

## Development

### Prerequisites

- Node.js
- Hardhat
- Foundry

### Installation

```bash
# Clone the repository
git clone https://github.com/[your-username]/worldflag-contracts
cd worldflag-contracts

# Install dependencies
npm install

# Install Foundry dependencies
forge install
```

### Testing

The project uses both Hardhat and Foundry for comprehensive testing coverage.

```bash
# Run Hardhat tests
npx hardhat test

# Run Foundry tests
forge test
```

### Deployment

```bash
# Deploy to local network
npx hardhat run scripts/deploy.js --network localhost

# Deploy to testnet/mainnet (requires configuration)
npx hardhat run scripts/deploy.js --network [network-name]
```

## Security

- All contracts use OpenZeppelin's battle-tested implementations
- World ID integration prevents sybil attacks
- Rate limiting prevents spam
- UUPS proxy pattern allows for security upgrades

## License

[Add your license here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
