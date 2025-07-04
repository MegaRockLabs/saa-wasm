#[cfg(all(feature = "cosmwasm_v1", not(feature = "cosmwasm")))]
pub use cw_storage_plus_one as cw_storage_plus;

use cw_storage_plus::{Item, Map};
use smart_account_auth::{CredentialInfo, CredentialId};
use crate::wasm::{StdError, Storage, Order};
use crate::serde::{de::DeserializeOwned, Serialize};
use crate::errors::StorageError;


/// The credential ID to use by default for verifications
pub const PRIMARY_ID : Item<CredentialId> = Item::new("cw_auth_ver");


// whether there are native callers to authorize easily
pub const HAS_NATIVES : Item<bool> = Item::new("cw_auth_hn");


/// Mapping of credential IDs to credential additional information.
pub const CREDENTIAL_INFOS: Map<CredentialId, CredentialInfo> = Map::new("cw_auth_creds");


/// Current account number or nonce that must be used for replay attack protection
pub const ACCOUNT_NUMBER : Item<u64> = Item::new("cw_auth_an");


/// Storage of session keys
#[cfg(feature = "session")]
pub const SESSIONS: Map<String, smart_account_auth::Session> = Map::new("cw_auth_ses");



// Feauture only because not used elsewhere
pub fn item_exist<T>(
    storage: &mut dyn Storage,
    item: &Item<T>,
) -> bool 
    where T: Serialize + DeserializeOwned
{
    item.exists(storage)
}


pub fn map_has<T>(
    storage: &dyn Storage,
    map: &Map<String, T>,
    key: impl ToString,
) -> bool 
    where T: Serialize + DeserializeOwned
{
    map.has(storage, key.to_string())
}


pub fn map_get<T>(
    storage: &dyn Storage,
    map: &Map<String, T>,
    key: impl ToString,
    name: &str
) -> Result<T, StorageError> 
    where T: Serialize + DeserializeOwned
{
    map
    .load(storage, key.to_string())
    .map_err(|e| StorageError::Read(name.to_string(), e.to_string()))
}



pub fn map_save<T>(
    storage: &mut dyn Storage,
    map: &Map<String, T>,
    key: &String,
    value: &T,
    name: &str
) -> Result<(), StorageError> 
    where T: Serialize + DeserializeOwned
{
    map.save(storage, key.clone(), value)
    .map_err(|e| StorageError::Write(name.to_string(), e.to_string()))
}


pub fn map_remove<T>(
    storage: &mut dyn Storage,
    map: &Map<String, T>,
    key: impl ToString,
) where T: Serialize + DeserializeOwned {
    map.remove(storage, key.to_string());
}



pub fn get_map_records<V>(
    storage: &dyn Storage,
    map: &Map<String, V>,
    name: &str
) -> Result<Vec<(String, V)>, StorageError> 
    where V: Serialize + DeserializeOwned
{
    map
    .range(storage, None, None, Order::Ascending)
    .collect::<Result<Vec<(CredentialId, V)>, StdError>>()
    .map_err(|e| StorageError::Read(name.to_string(), e.to_string()))
}






pub fn delete_map_records<V>(
    storage: &mut dyn Storage,
    map: &Map<String, V>,
    _: &str
) -> Result<(), StorageError> 
    where V: Serialize + DeserializeOwned
{
    map.clear(storage);
    Ok(())
}