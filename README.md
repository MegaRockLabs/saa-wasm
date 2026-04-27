# Smart Account Auth: CosmWasm

A split from the original library that took away the pieces for interaction with the storage and defines certain authentication-related mechanisms like session keys in ways that meet the needs of the Wasm VMs uniquely.

## Experimental

In heavy development. Use at your own risk.

### Major Changes

The default behavior without the replay attack protection (which was activated using the `replay` tag) is not supported anymore and the replay attack protection is now the default.

Some other aspects that were optional like the `iterator` feature tag are always enabled and it isn't configurable.

## Usage

### Installation / Saving to Storage

To automatically validate, add the native sender if asked, check that the message is fresh in terms of replay attack protection, and in the end store all necessary info all in one, you can use the `save_credentials` method.

```rust
// if you don't use or allow native caller addresses the `info` (of `MessageInfo`) is not used
save_credentials(deps.api, deps.storage, &env, &info, &credential_data)?;
```

### Verification

To verify that an action can be performed by an address verified by the native cryptography of the chain node:

```rust
verify_native(deps.storage, &info.sender)?;
```

To verify using the custom authenticators from the stored credential info and the new data payload:

```rust
// non mutable storage reference. Can get from both `Deps` and `DepsMut`
verify_signed(deps.api, deps.storage, &env, signed_data_msg)?;
```

This method is meant for queries, e.g., `CanExecute` defined in `cw1` or `ValidSignature` from `cw82`. For actions inside a transaction, use `increment_account_number` hidden under a feature tag.

The intended method for verifying actions in a transaction that automatically increments the account number (nonce) is:

```rust
// mutable storage reference. Can only get from `DepsMut`
verify_signed_actions(deps.api, deps.storage, &env, data)?;
```

### Updating Credentials

Methods for updating the stored credentials expect that the authorization has been performed prior to the invocation.

The credentials can be updated with `update_credentials` or with more specific ones for addition and removal respectively:

```rust
update_credentials(deps.api, deps.storage, &env, &update_operation)?;
```

During addition in `update_credentials` or when calling `add_credentials` directly, each passed credential goes through all the standard checks to establish the ownership.

If you are checking the authorization using the signed payload, you either use `verify_signed` and have the same nonce everywhere, or use `verify_signed_actions` but ask the user to sign an incremental nonce when generating signatures for the new ones to be added.

The first is more preferable to avoid confusion. This is the only place where you should be using `verify_signed` inside a transaction (not in a query). There might be other scenarios in the future where you do need the old nonce after the authorization and you can use it there as well.

## Registry / Factory (Pattern)

In some cases you might want to pass credentials to an account to be created. Since the replay attack protection envelope includes a contract address and nonce, it might be problematic. As a reminder, the envelope is defined as follows:

```rust
pub struct MsgDataToSign<M = String> {
    pub chain_id: String,
    pub contract_address: String,
    pub messages: Vec<M>,
    pub nonce: Uint64,
}
```

### Nonce and Messages

By default, if the nonce isn't found in the storage, it's assumed to be `0` when verifying the credentials the first time. Even if there weren't any signed credentials and only native addresses, after the saving was completed the nonce is set to `1`.

If you suspect that there are contracts using the same address and the same flow, make sure to define and check the `messages` field to contain data defined by you. It is completely ignored by the library. It can contain a `String` identifying your registry / accounts or their versions, or a timestamp / block height that are fresh enough with the given `Env` object.

### Contract Address

One way to fix the situation with addresses is to use a method for creating an account with a pre-determined address (e.g., `instantiate2`).

If it isn't available but you use a factory / registry pattern, you can use the address of a parent contract.
Inside the instantiation logic of a new account, you can replace the `Env` object with the overridden address:

```rust
// Account Contract

let registry_env = Env {
    contract: ContractInfo { address: info.sender.clone() },
    ..env.clone()
};
```

#### Native Callers

If you allow native addresses, make sure to pass down the original sender from the entrypoint to the account and then modify it as well:

```rust
let native_info = MessageInfo {
    sender: address_that_called_the_first_contract.clone(),
    funds: info.funds.clone(),
};
```

In the end, you can call the saving method and it should work as expected:

```rust
save_credentials(deps.api, deps.storage, &registry_env, &native_info, &credential_data)?;
```

### Chain ID

In the significant majority of cases, both the registry and the accounts are deployed to the same chain and therefore use the same chain ID. In case you create accounts over a cross-chain messaging protocol like IBC, the general advice is to use the ID of the chain where the accounts are created.

In case you need the credentials stored in the registry, you either extract all the info and store them with your logic manually, or pass down a redefined `Env` the same way we did for the address but with the overridden `chain_id` instead.

```rust
// Registry Contract

let account_env = Env {
    block: {
        chain_id:  accounts_chain_id.clone(),
        ..env.block.clone()
    },
    ..env.clone()
};

save_credentials(deps.api, deps.storage, &account_env, &info, &credential_data)?;
```
