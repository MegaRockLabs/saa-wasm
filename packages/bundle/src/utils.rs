use types::{
    errors::StorageError, stores::{get_map_records, CREDENTIAL_INFOS as CREDS}, 
    wasm::Storage
};

use smart_account_auth::CredentialRecord;


pub fn has_natives(
    storage: &dyn Storage
) -> bool {
    types::stores::HAS_NATIVES.load(storage).unwrap_or(false)
}



pub fn get_credentials(
    storage: &dyn Storage
) -> Result<Vec<CredentialRecord>, StorageError> {
    get_map_records(storage, &CREDS, "credentials")
}





#[cfg(feature = "utils")]
pub fn increment_account_number(
    storage: &mut dyn Storage
) -> Result<(), StorageError> {
    use types::stores::ACCOUNT_NUMBER;
    if ACCOUNT_NUMBER.exists(storage) {
        ACCOUNT_NUMBER.save(storage, &1u64)
        .map_err(|e| StorageError::Write(
            "initial account number".to_string(), 
            e.to_string()
        ))?;
    } else {
        ACCOUNT_NUMBER.update(storage, |n| 
            Ok::<u64, types::wasm::StdError>(n + 1)
        )
        .map_err(|e| StorageError::Write(
            "updated account number".to_string(), 
            e.to_string()
        ))?;
    }
    Ok(())
}




#[cfg(feature = "utils")]
pub fn credential_count(storage: &dyn Storage) -> usize {
    CREDS.keys_raw(storage, None, None, types::wasm::Order::Ascending).count()
}

