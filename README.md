# Compliance Vault

A Clarity smart contract implementing compliance-aware vaults with pluggable validation modules for the Stacks blockchain.

## Features

- **Modular Compliance**: Pluggable validation modules that can be enabled/disabled per vault
- **Flexible Administration**: Admin controls for registering and updating compliance modules
- **Event Tracking**: Comprehensive event emission for vault operations
- **Access Control**: Owner-based permissions for vault operations
- **Safety Checks**: Built-in validation for all operations

## Contract Functions

### Vault Management
- `create-vault`: Create a new vault
- `fund-vault`: Deposit STX into a vault
- `withdraw`: Withdraw STX from a vault

### Module Management  
- `register-module`: Register a new compliance module (admin only)
- `set-module-principal`: Update an existing module (admin only)
- `set-vault-module`: Enable/disable modules for a specific vault

### Read-Only Views
- `get-vault`: Get vault details
- `get-module`: Get module details
- `is-module-enabled-for-vault`: Check if a module is enabled
- `get-module-counter`: Get total number of registered modules
