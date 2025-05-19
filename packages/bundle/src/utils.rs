use types::{
    cosmwasm_std::{from_json, Api, Binary, Env, Storage}, 
    errors::{AuthError, ReplayError, StorageError}, 
    stores::{get_map_records, map_get, VERIFYING_ID, CREDENTIAL_INFOS as CREDS}, 
    Credential, CredentialRecord, MsgDataToSign, MsgDataToVerify, SignedDataMsg
};




pub fn get_credential_records(
    storage: &dyn Storage
) -> Result<Vec<CredentialRecord>, StorageError> {
    get_map_records(storage, &CREDS, "credentials")
}




 fn parse_cred_args(
    id: &str,
    msg: &SignedDataMsg
) -> (String, Option<String>, Option<Binary>) {
    match &msg.payload {
        Some(payload) => {
            let id = match &payload.credential_id {
                Some(id) => id.to_lowercase(),
                None => id.to_string(),
            };
            (id, payload.hrp.clone(), payload.extension.clone())
            
        }   
        None => (id.to_string(), None, None)
    }
}


pub fn cred_from_signed(
    api : &dyn Api,
    storage:  &dyn Storage,
    msg: SignedDataMsg,
) -> Result<Credential, AuthError> {
    let (id, hrp, ext) = parse_cred_args(
        VERIFYING_ID.load(storage).map_err(|_| AuthError::NoCredentials)?.as_str(),
        &msg
    );
    
    let mut info = map_get(storage, &CREDS, &id, "credential")
        .map_err(|e| AuthError::generic(e.to_string()))?;

    info.hrp = hrp.or(info.hrp);
    let cred = construct_credential((id, info), msg, ext)?;
    cred.verify_cosmwasm(api)?;
    Ok(cred)
}





#[cfg(feature = "session")]
pub fn session_cred_from_signed(
    api : &dyn Api,
    storage:  &dyn Storage,
    key: &str,
    msg: SignedDataMsg,
) -> Result<Credential, AuthError> {
    let (id, hrp, ext) = parse_cred_args( key, &msg);
    let session = map_get(storage, &super::stores::SESSIONS, &id, "session key")
        .map_err(|e| AuthError::generic(e.to_string()))?;

    let mut info = session.grantee.1.clone();
    info.hrp = hrp.or(info.hrp);
    let cred = construct_credential((id, info), msg, ext)?;
    cred.verify_cosmwasm(api)?;
    Ok(cred)
}


fn construct_credential(
    _info: (String, types::CredentialInfo), 
    _msg: SignedDataMsg, 
    _ext: Option<Binary>
) -> Result<Credential, AuthError> {
    todo!()
}





pub fn convert<M : saa_schema::serde::de::DeserializeOwned>(
    data: &[u8]
) -> Result<MsgDataToSign<M>, ReplayError> {
    from_json(data)
    .map_err(|_| ReplayError::Convertion("MsgDataToSign".to_string()))
}



pub fn convert_validate(
    data: &[u8],
    env: &Env,
    nonce: u64
) -> Result<(), ReplayError> {
    let msg : MsgDataToVerify = from_json(data)
                            .map_err(|_| ReplayError::Convertion("MsgDataToVerify".to_string()))?;
    msg.validate(env, nonce)?;
    Ok(())
}



pub fn convert_validate_return<M : saa_schema::serde::de::DeserializeOwned>(
    data: &[u8],
    env: &Env,
    nonce: u64
) -> Result<MsgDataToSign<M>, ReplayError> {
    let msg  = convert(data)?;
    msg.validate(env, nonce)?;
    Ok(msg)

}
