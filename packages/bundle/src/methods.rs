use types::{
    stores::{ACCOUNT_NUMBER, CREDENTIAL_INFOS}, 
    wasm::{Order, StdError, Storage}, 
    errors::StorageError, 
};

use smart_account_auth::{CredentialId};





pub fn increment_account_number(
    storage: &mut dyn Storage
) -> Result<(), StorageError> {
    if ACCOUNT_NUMBER.exists(storage) {
        ACCOUNT_NUMBER.save(storage, &1u64)
        .map_err(|e| StorageError::Write(
            "initial account number".to_string(), 
            e.to_string()
        ))?;
    } else {
        ACCOUNT_NUMBER.update(storage, |n| 
            Ok::<u64, StdError>(n + 1)
        )
        .map_err(|e| StorageError::Write(
            "updated account number".to_string(), 
            e.to_string()
        ))?;
    }
    Ok(())
}




pub fn has_credential(
    storage: &dyn Storage,
    id: CredentialId
) -> bool {
    CREDENTIAL_INFOS.has(storage, id)
}



pub fn credential_count(storage: &dyn Storage) -> usize {
    CREDENTIAL_INFOS.keys_raw(storage, None, None, Order::Ascending).count()
}



#[cfg(feature = "session")]
pub fn get_session_records(
    storage: &dyn Storage,
) -> Result<Vec<(String, smart_account_auth::Session)>, StorageError> {
    types::stores::get_map_records(storage, &types::stores::SESSIONS, "session keys")
}
