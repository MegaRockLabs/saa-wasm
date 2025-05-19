mod utils;
#[cfg(feature = "utils")]
mod methods;
#[cfg(feature = "session")]
mod session;



#[cfg(feature = "session")]
pub use {
    session::{handle_session_actions, handle_session_queries},
    types::queries::{SessionQueryMsg, SessionQueriesMatch, QueryUsesActions, QueryResTemplate},
    types::actions::{SessionActionMsg, SessionActionsMatch}
};
#[cfg(feature = "utils")]
pub use {
    methods::*,
    utils::*,
};
#[cfg(feature = "types")]
pub use types;





use types::{
    traits::Verifiable,
    errors::{AuthError, StorageError}, 
    cosmwasm_std::{Api, Env, MessageInfo, Storage}, 
    stores::{ACCOUNT_NUMBER, CREDENTIAL_INFOS as CREDS, HAS_NATIVES, VERIFYING_ID},
    StoredCredentials, CredentialData, CredentialRecord, CredentialInfo, CredentialName, CredentialId,
    ensure, SignedDataMsg, serde, stores, UpdateOperation,
};


pub fn account_number(
    storage: &dyn Storage
) -> u64 {
    ACCOUNT_NUMBER.load(storage).unwrap_or(0)
}




pub fn verify_native(
    storage: &dyn Storage,
    sender: String
) -> Result<(), StorageError> {
    ensure!(CREDS.has(storage, sender), StorageError::NotFound);
    Ok(())
}


pub fn verify_signed(
    api: &dyn Api,
    storage: &dyn Storage,
    env: &Env,
    msg: SignedDataMsg
) -> Result<(), AuthError> {
    utils::convert_validate(msg.data.as_slice(), env, account_number(storage))?;
    utils::cred_from_signed(api, storage, msg)?;
    Ok(())
} 



pub fn verify_signed_actions<T : serde::de::DeserializeOwned>(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    msg: SignedDataMsg
) -> Result<Vec<T>, AuthError> {
    let nonce = account_number(storage);
    let signed = utils::convert_validate_return(msg.data.as_slice(), env, nonce)?;
    utils::cred_from_signed(api, storage, msg)?;
    ACCOUNT_NUMBER.save(storage, &(nonce + 1))?;
    Ok(signed.messages)
}





pub fn has_natives(
    storage: &dyn Storage
) -> bool {
    HAS_NATIVES.load(storage).unwrap_or(false)
}



pub fn get_stored_credentials(
    storage: &dyn Storage
) -> Result<StoredCredentials, StorageError> {

    Ok(StoredCredentials { 
        has_natives: has_natives(storage),
        verifying_id: stores::VERIFYING_ID.load(storage).map_err(|_| StorageError::NotFound)?,
        records: utils::get_credential_records(storage)?,
        account_number: account_number(storage), 
        #[cfg(feature = "session")]
        sessions    :   None,
    })
}




pub fn save_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    data: &CredentialData
) -> Result<CredentialData, AuthError> {
    let data = data.with_native(info);
    data.validate()?;
    data.checked_replay( env, 0u64)?;

    ACCOUNT_NUMBER.save(storage, &1u64)?;

    let mut has_natives = false;
    for cred in data.credentials.iter() {
        cred.verify_cosmwasm(api)?;
        let info = cred.info();
        if info.name == CredentialName::Native { 
            has_natives = true 
        }
        CREDS.save(storage, cred.id(), &info)?;
    }
    HAS_NATIVES.save(storage, &has_natives)?;

    let verifying = match data.primary_index {
        Some(i) => data.credentials[i as usize].id(),
        None => data.credentials.first().unwrap().id()
    };
    VERIFYING_ID.save(storage, &verifying)?;
    Ok(data)
}







pub fn reset_credentials(
    storage: &mut dyn Storage,
    acc_number: bool,
    #[cfg(feature = "session")]
    sessions: bool
) -> Result<(), StorageError> {
    VERIFYING_ID.remove(storage);
    HAS_NATIVES.remove(storage);
    CREDS.clear(storage);
    if acc_number {
        ACCOUNT_NUMBER.remove(storage);
    }
    #[cfg(feature = "session")]
    {
        if sessions {
            types::stores::SESSIONS.clear(storage);
        }
    }
    Ok(())
}




/* pub fn update_credentials_signed(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    msg: SignedDataMsg
) -> Result<(), AuthError> {

    let nonce = account_number(storage);
    let signed : MsgDataToSign<UpdateOperation> = convert_validate_return(
        msg.data.as_slice(), env, nonce
    )?;
    let cred = cred_from_signed(api, storage, msg)?;

    for op in signed.messages {
        let had_natives = HAS_NATIVES.load(storage)?;
        match op {
            UpdateOperation::Add(data) => {
                data.with_credential(cred.clone()).validate_replay_all(storage, env)?;
                add_credentials(api, storage, data.with_native(info.sender.as_str()), had_natives)?;
            },
            UpdateOperation::Remove(idx) => {
                remove_credentials(storage, idx, had_natives)?;
            }
        }
    }
    ACCOUNT_NUMBER.save(storage, &(nonce + 1))?;
    Ok(())
}
 */



pub fn update_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    op: UpdateOperation,
) -> Result<(), AuthError> {
    let had_natives = HAS_NATIVES.load(storage)?;
    match op {
        UpdateOperation::Add(data) => {
            add_credentials(api, storage, data, had_natives)
        },
        UpdateOperation::Remove(idx) => {
            remove_credentials(storage, idx, had_natives)?;
            Ok(())
        }
    }
}





pub fn add_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    data: CredentialData,
    had_natives: bool
) -> Result<(), AuthError> {
    
    data.validate()?;
    data.verify_cosmwasm(api)?;

    if let Some(ix) = data.primary_index {
        VERIFYING_ID.save(storage, &data.credentials[ix as usize].id())?;
    }

    let mut has_natives = had_natives;

    for cred in data.credentials.iter() {
        let id = cred.id();
        ensure!(!CREDS.has(storage, id.clone()), StorageError::AlreadyExists);
        let info = cred.info();
        if !has_natives && info.name == CredentialName::Native {
            has_natives = true;
        }
        CREDS.save(storage, id, &info)?;
    }

    if !had_natives && has_natives {
        HAS_NATIVES.save(storage, &true)?;
    }   

    if !VERIFYING_ID.exists(storage) {
        VERIFYING_ID.save(storage, &data.credentials[0].id())?;
    }
    Ok(())
}



pub fn remove_credentials(
    storage: &mut dyn Storage,
    idx: Vec<CredentialId>,
    had_natives: bool
) -> Result<Vec<CredentialRecord>, AuthError> {
    ensure!(!idx.is_empty(), AuthError::generic("Must supply at least one credential to remove"));

    let all_creds = utils::get_credential_records(storage)?;
    let left = all_creds.len() - idx.len();
    ensure!(left > 0, AuthError::generic("Must leave at least one credential"));

    let verifying_id = VERIFYING_ID.load(storage)?;
    let mut native_changed = false;
    let mut verifying_removed = false;

    let remaining : Vec<(String, CredentialInfo)> = all_creds
        .into_iter()
        .filter(|(id, info)| {
            if idx.contains(id) {
                if info.name == CredentialName::Native {
                    native_changed = true;
                }
                if *id == verifying_id {
                    verifying_removed = true;
                }
                CREDS.remove(storage, id.to_string());
                false
            } else {
                true
            }
        }).collect();
        
    if had_natives && native_changed {
        let still_has = remaining
            .iter()
            .any(|(_, info)| info.name == CredentialName::Native);
        HAS_NATIVES.save(storage, &still_has)?;
    }

    if verifying_removed {
        let first = remaining.first().unwrap();
        VERIFYING_ID.save(storage, &first.0)?;
    }

    Ok(remaining)
}

