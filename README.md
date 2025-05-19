# cw-auth


### Storage / Replay

The library is aim tp provide helpful primitives for verifying and then storing credentials in a secure and easy way
```rust
# first verify all the credentials and then store them stored in the storage
credential_data.save_cosmwasm(deps.api, deps.storage, &env, &info)?;
```

When replay attack protection is enabled, the library will enforce the message to include a contract address, a chain id and a nonce that should be equal to the current account number
 

After a successful verification an account contract must increment the nonce to prevent replay attacks
```rust
increment_account_number(deps.storage)?;
```

The library also provides a helper function to verify the signed actions which will verify the credentials and then increment the nonce automatically
```rust
verify_signed_actions(deps.api, deps.storage, &env, data)?;
```

#### Registries / Factories

In some cases you can want to use credemtials for accounts that are not yet created and therefire do not have an account number (unless instantiate2 is used). 

In cases like that you can use address of a registry / factory contract in data to sign. Later after the account contract is created you can create a new `Env` object with overwritten contract address

```rust
let registry_env = Env {
    contract: ContractInfo { address: info.sender.clone() },
    ..env.clone()
};

data.save_cosmwasm(api, storage, &registry_env, &info)?;
```