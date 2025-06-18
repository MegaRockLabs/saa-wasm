use types::{
    errors::{AuthError, StorageError}, stores::{get_map_records, map_get, CREDENTIAL_INFOS as CREDS}, 
    wasm::{Deps, Storage}
};

use smart_account_auth::{
    build_credential, msgs::SignedDataMsg, 
    types::{errors::CredentialError, exts::PayloadExtension}, 
    Credential, CredentialRecord
};



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





pub fn cred_from_signed(
    deps: Deps,
    msg: SignedDataMsg,
) -> Result<Credential, AuthError> {
    let (id, hrp, ext) = parse_cred_args(
        types::stores::PRIMARY_ID.load(deps.storage)
            .map_err(|_| CredentialError::NoCredentials)?.as_str(),
        &msg
    );
    let mut info = map_get(deps.storage, &CREDS, &id, "credential")?;
    info.hrp = hrp.or(info.hrp);
    let cred = build_credential((id, info), msg, ext)?;
    cred.verify(deps)?;
    Ok(cred)
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


#[cfg(feature = "utils")]
pub fn credential_count(storage: &dyn Storage) -> usize {
    CREDS.keys_raw(storage, None, None, types::wasm::Order::Ascending).count()
}



#[cfg(all(feature = "session", feature = "utils"))]
pub fn get_session_records(
    storage: &dyn Storage,
) -> Result<Vec<(String, smart_account_auth::Session)>, StorageError> {
    types::stores::get_map_records(storage, &types::stores::SESSIONS, "session keys")
}




#[cfg(feature = "session")]
pub fn session_cred_from_signed(
    deps: Deps,
    key: &str,
    msg: SignedDataMsg,
) -> Result<Credential, AuthError> {
    use smart_account_auth::build_credential;

    let (id, hrp, ext) = parse_cred_args(key, &msg);
    let session = map_get(
        deps.storage, &types::stores::SESSIONS, &id, "session key")
        .map_err(|e| AuthError::generic(e.to_string())
    )?;

    let mut info = session.grantee.1.clone();
    info.hrp = hrp.or(info.hrp);
    let cred = build_credential((id, info), msg, ext)?;
    cred.verify(deps)?;
    Ok(cred)
}



fn parse_cred_args(
    id: &str,
    msg: &SignedDataMsg
) -> (String, Option<String>, Option<PayloadExtension>) {

    match &msg.payload {
        Some(payload) => {
            let id = payload.credential_id
                .clone()
                .unwrap_or(id.to_string());

            (id, payload.hrp.clone(), payload.extension.clone())
            
        }   
        None => (id.to_string(), None, None)
    }
}

