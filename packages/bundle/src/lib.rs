#[cfg(feature = "session")]
mod session;
mod utils;

#[cfg(feature = "types")]
pub use {types::stores, smart_account_auth as saa_types};
#[cfg(feature = "utils")]
pub use utils::*;


#[cfg(feature = "session")]
pub use {
    session::{handle_session_action, handle_session_query},
    types::{
        macros::{session_query, session_action},
        sessions::{queries::*, actions::*}
    }
};

pub use types::{
    StoredCredentials, UpdateOperation
};


use smart_account_auth::{
    CheckOption, Credential, CredentialId, CredentialName, CredentialRecord, 
    ReplayParams, ReplayProtection, VerifiedData
};

use types::{
    stores::{ACCOUNT_NUMBER, HAS_NATIVES, PRIMARY_ID, CREDENTIAL_INFOS as CREDS}, 
    errors::{AuthError, CredentialError, ReplayError, StorageError}, 
    wasm::{ensure, Env, Storage}, 
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


#[cfg(feature = "signed")]
pub fn verify_data(
    deps: Deps,
    msg: SignedDataMsg
) -> Result<(), AuthError> {
    utils::cred_from_signed(deps, msg)?;
    Ok(())
} 



#[cfg(feature = "signed")]
pub fn verify_signed<T : Serialize + Display + Clone>(
    deps: Deps,
    env: &Env,
    messages: Vec<T>,
    signed: SignedDataMsg
) -> Result<(), AuthError> {
    let msgs = messages.iter()
        .map(|m| m.to_string())
        .collect::<Vec<String>>();
    let nonce = account_number(deps.storage);
    let cred = utils::cred_from_signed(deps, signed)?;
    cred.protect_reply(env, ReplayParams::new(nonce, CheckOption::Messages(msgs)))?;
    Ok(())
}


#[cfg(feature = "signed")]
pub fn verify_signed_actions<T : Serialize + Display + Clone>(
    deps: &mut DepsMut,
    env: &Env,
    messages: Vec<T>,
    signed: SignedDataMsg
) -> Result<(), AuthError> {
    let msgs = messages.iter()
        .map(|m| m.to_string())
        .collect::<Vec<String>>();
    let nonce = account_number(deps.storage);
    let cred = utils::cred_from_signed(deps.as_ref(), signed)?;
    cred.protect_reply(env, ReplayParams::new(nonce, CheckOption::Messages(msgs)))?;
    ACCOUNT_NUMBER.save(deps.storage, &(nonce + 1))?;
    Ok(())
}



pub fn verify_cred_query(
    storage: &dyn Storage,
    env: &Env,
    cred: Credential,
    messages: Option<Vec<String>>
) -> Result<u64, AuthError> {
    let nonce = account_number(storage);
    let check_option = match messages {
        Some(msgs) => CheckOption::Messages(msgs),
        None => CheckOption::Nothing,
    };
    cred.protect_reply(env, ReplayParams::new(nonce, check_option))?;
    Ok(nonce + 1)
}



pub fn verify_cred_actions(
    storage: &mut dyn Storage,
    env: &Env,
    cred: Credential,
    messages: Option<Vec<String>>
) -> Result<(), AuthError> {
    let new_nonce = &verify_cred_query(storage, env, cred, messages)?;
    ACCOUNT_NUMBER.save(storage, new_nonce)?;
    Ok(())
}





pub fn get_stored_credentials(
    storage: &dyn Storage
) -> Result<StoredCredentials, StorageError> {
    Ok(StoredCredentials { 
        has_natives     :   utils::has_natives(storage),
        records         :   utils::get_credentials(storage)?,
        account_number  :   account_number(storage), 
        primary_id      :   PRIMARY_ID.load(storage).map_err(|_| StorageError::NotFound)?,
        #[cfg(feature = "session")]
        sessions        :   session::get_session_records(storage)?,
    })
}



pub fn save_credentials(
    storage: &mut dyn Storage,
    data: &VerifiedData
) -> Result<(), StorageError> {
    ACCOUNT_NUMBER.save(storage, &data.nonce)?;
    PRIMARY_ID.save(storage, &data.primary_id)?;
    HAS_NATIVES.save(storage, &data.has_natives)?;
    data.credentials
        .iter()
        .try_for_each(|(id, info)| 
            CREDS.save(storage, id.clone(), info))
        .map_err(|e| StorageError::Write("credentials".to_string(), e.to_string()))
}





pub fn has_credential(
    storage: &dyn Storage,
    id: smart_account_auth::CredentialId,
    name: Option<smart_account_auth::CredentialName>
) -> bool {
    if let Some(name) = name {
        CREDS.load(storage, id)
            .map(|c|c.name == name)
            .unwrap_or(false)
    } else {
        CREDS.has(storage, id)
    }
}




pub fn reset_credentials(
    storage: &mut dyn Storage,
    acc_number: bool,
    #[cfg(feature = "session")]
    sessions: bool
) -> Result<(), StorageError> {
    PRIMARY_ID.remove(storage);
    HAS_NATIVES.remove(storage);
    CREDS.clear(storage);
    if acc_number { ACCOUNT_NUMBER.remove(storage); }
    #[cfg(feature = "session")]
    if sessions {
        types::stores::SESSIONS.clear(storage);
    }
    Ok(())
}



pub fn update_credentials(
    storage  :  &mut dyn Storage,
    op: &UpdateOperation<VerifiedData>,
) -> Result<(), AuthError> {
    match op {
        UpdateOperation::Add(data) => {
            add_credentials(storage, &data)?;
        },
        UpdateOperation::Remove(idx) => {
            remove_credentials(storage, idx)?;
        }
    }
    Ok(())
}



pub fn add_credentials(
    storage  :  &mut dyn Storage,
    data     :  &VerifiedData,
) -> Result<(), AuthError> {
    let nonce = ACCOUNT_NUMBER.load(storage).unwrap_or(0);
    ensure!(data.nonce == nonce, ReplayError::InvalidNonce(nonce));
    if data.override_primary { PRIMARY_ID.save(storage, &data.primary_id)?; };
    ACCOUNT_NUMBER.save(storage, &(nonce +1))?;
    HAS_NATIVES.update(storage, |had_natives| Ok::<bool, StorageError>(had_natives || data.has_natives))?;

    data.credentials
        .iter()
        .try_for_each(|(id, info)| {
            CREDS.save(storage, id.clone(), &info)
            .map_err(|e| AuthError::Storage(
                StorageError::Write(id.to_string(), e.to_string())
            ))
        }
    )
}



pub fn remove_credentials(
    storage: &mut dyn Storage,
    idx: &Vec<CredentialId>,
) -> Result<Vec<CredentialRecord>, AuthError> {
    ensure!(!idx.is_empty(), CredentialError::NoCredentials);

    let idx = idx.iter()
        .map(|id| id.clone())
        .collect::<Vec<_>>();
    
    let all_creds = utils::get_credentials(storage)?;
    let had_natives = HAS_NATIVES.load(storage)?;
    let verifying_id = PRIMARY_ID.load(storage)?;

    let (to_remove, remaining): (Vec<_>, Vec<_>) = all_creds
        .into_iter()
        .partition(|(id, _)| idx.contains(id));

    ensure!(!remaining.is_empty(), CredentialError::NoneLeft);

    let (
        native_changed, 
        verifying_removed
    ) = to_remove
        .into_iter()
        .fold((false, false), |(
            mut has_native, 
            mut has_verifying
        ), (id, info)| {
            if info.name == CredentialName::Native {
                has_native = true;
            }
            if id == verifying_id {
                has_verifying = true;
            }
            CREDS.remove(storage, id);
            (has_native, has_verifying)
    });


    if had_natives && native_changed {
        let still_has = remaining
            .iter()
            .any(|(_, info)| info.name == CredentialName::Native);
        HAS_NATIVES.save(storage, &still_has)?;
    }

    if verifying_removed {
        if let Some((id, _)) = remaining.first() {
            PRIMARY_ID.save(storage, id)?;
        } else {
            return Err(CredentialError::NoneLeft.into());
        }
    }

    Ok(remaining)
}

