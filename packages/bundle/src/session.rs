use smart_account_auth::{
    msgs::{Action, AllQueryDerivation, MsgDataToSign, SignedDataMsg}, 
    Caller, Credential, DerivableMsg, Session
};
use types::{
    sessions::{
        actions::{MsgArg, SessionAction, SessionActionMsg}, 
        queries::{QueryUsesActions, SessionQueryMsg}
    }, 
    wasm::{
        ensure, to_json_binary, Api, Binary, 
        Deps, DepsMut, Env, MessageInfo, Response, 
        StdError, StdResult, Storage
    }, 
    errors::{AuthError, SessionError, StorageError}, 
    stores::{map_get, map_remove, map_save, SESSIONS}, 
    strum::{IntoDiscriminant, VariantArray, VariantNames}, 
    serde::{self, Serialize}, 
};

use crate::{utils::session_cred_from_signed, verify_native, verify_signed_actions};

/* 
pub enum AdminAuth {
    
}
 */


fn validate_common(
    deps: Deps,
    session: &Session,
    cred    : &Credential,
    msgs    : &MsgArg<impl DerivableMsg>
) -> Result<(), AuthError> {
    let (id, info) = session.grantee.clone();
    ensure!(id == cred.id(), SessionError::NotGrantee);
    let cred_info = cred.verify(deps)?;
    ensure!(info == cred_info, SessionError::InvalidGrantee);
    #[cfg(not(feature = "multi"))]
    ensure!(session.can_do_msg(msgs), SessionError::NotAllowedAction);
    #[cfg(feature = "multi")]
    ensure!(msgs.iter().all(|m| session.can_do_msg(m)), SessionError::NotAllowedAction);
    Ok(())
}


pub fn verify_session_native(
    deps: Deps,
    address: &str,
    session: &Session,
    msgs    : &MsgArg<impl DerivableMsg>
) -> Result<(), AuthError> {
    let caller : Caller = address.into();
    validate_common(deps, session, &caller.into(), msgs)
}


pub fn verify_session_signed<T : Serialize + DerivableMsg>(
    deps: &mut DepsMut,
    env: &Env,
    key: &String,
    session: &mut Session,
    msgs: MsgArg<T>,
    signed: SignedDataMsg
) -> Result<(), AuthError> {
    #[cfg(feature = "multi")]
    let messages = msgs.iter().map(|m|m.to_json_string()).collect::<Result<Vec<String>, _>>()?;
    #[cfg(not(feature = "multi"))]
    let messages = vec![msgs.to_json_string()?];
    let nonce = session.nonce.clone();
    let envelope = to_json_binary(&MsgDataToSign {
        nonce: nonce.into(),
        chain_id: env.block.chain_id.clone(),
        contract_address: env.contract.address.to_string(),
        messages,
    })?;
    ensure!(envelope == signed.data, AuthError::generic("Data mismatch in signed message"));
    let deps_ref = deps.as_ref();
    let cred = session_cred_from_signed(deps_ref,  key, signed)?;
    validate_common(deps_ref, &session, &cred, &msgs)?;
    session.nonce = nonce + 1;
    map_save(deps.storage, &SESSIONS, key, &session, "session key")?;
    Ok(())
}






pub fn update_session(
    storage: &mut dyn Storage,
    key: &String,
    session: &Session,
) -> Result<u64, StorageError> {
    let session = match map_get(storage, &SESSIONS, key, "session key") {
        Ok(loaded) => &Session { nonce: loaded.nonce + 1, ..session.clone() },
        Err(_) => session,
    };
    map_save(storage, &SESSIONS, &key, session, "session key")?;
    Ok(session.nonce)
}




pub fn handle_session_action<M, F, E>(
    mut deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    action: SessionAction<M>,
    admin: Option<String>,
    execute: F
) -> Result<Response, E> 
    where 
        M : serde::de::DeserializeOwned + DerivableMsg + core::fmt::Display , 
        F: Fn(&mut DepsMut, &Env, &MessageInfo, MsgArg<M>) -> Result<Response, E>,
        E: From<AuthError> + From<SessionError> + From<StorageError>,
{

    //let addr = admin.clone().unwrap_or(info.sender.to_string());
    use SessionActionMsg::*;

    Ok(match action.msg {

        WithSessionKey(with_msg) => {
            let key = &with_msg.session_key;
            let mut session = map_get(deps.storage, &SESSIONS, key, "session key")?;

            if session.expiration.is_expired(&env.block) {

                map_remove(deps.storage, &SESSIONS, key);
                Response::new()
                    .add_attribute("action", "with_session_key")
                    .add_attribute("session_key", key.as_str())
                    .add_attribute("status", "revoked")
                    .add_attribute("reason", "expired")

            } else {
                match action.signed {
                    Some(signed) => {
                        verify_session_signed(&mut deps, env, key, &mut session, with_msg.msgs.clone(), signed)?;
                    },
                    None => {
                        verify_session_native(deps.as_ref(),  info.sender.as_str(), &session, &with_msg.msgs)?;
                    }
                };
                execute(&mut deps, env, info, with_msg.msgs)?
                    .add_attribute("action", "with_session_key")
                    .add_attribute("session_key", key.as_str())
                    .add_attribute("status", "success")
                    .add_attribute("nonce", session.nonce.to_string().as_str())
            }
        },

        admin_action => {
            let granter = admin.unwrap_or(env.contract.address.to_string());
            match action.signed {
                Some(signed) => {
                    verify_signed_actions(&mut deps, env, vec![admin_action.clone()], signed)?;
                },
                None => {
                    verify_native(deps.storage, granter.clone())?;
                }
            }
            match admin_action {
                CreateSession(mut create) => {
                    create.session_info.granter = Some(granter);
                    let session = create.to_session(&env)?;
                    let key = session.key();
                    let nonce = update_session(deps.storage,  &key, &session)?;
                    Response::new()
                        .add_attribute("action", "create_session")
                        .add_attribute("session_key", key.as_str())
                        .add_attribute("nonce", nonce.to_string().as_str())
                }
                CreateSessionFromMsg(mut create) => {
                    create.session_info.granter = Some(granter);
                    let session = create.to_session(&env)?;
                    let key = session.key();
                    let nonce = update_session(deps.storage,  &key, &session)?;
                    let msg = create.msgs;
                    #[cfg(feature = "multi")]
                    let msg = vec![msg];
                    execute(&mut deps, env, info, msg)?
                            .add_attribute("action", "create_session_from_msg")
                            .add_attribute("session_key", key.as_str())
                            .add_attribute("nonce", nonce.to_string().as_str())
                }
                RevokeSession(msg) => {
                    let key = &msg.session_key;
                    if let Ok(loaded) = map_get(deps.storage, &SESSIONS, key, "session key") {
                        // anyone can revoke the expired session
                        if !loaded.expiration.is_expired(&env.block) {
                            ensure!(loaded.granter == granter, SessionError::NotOwner);
                        }
                        map_remove(deps.storage, &SESSIONS, key);
                        Response::new()
                            .add_attribute("action", "revoke_session")
                            .add_attribute("session_key", key.as_str())
                            .add_attribute("status", "revoked")
                    } else {
                        return Err(SessionError::NotFound.into())
                    }       
                }
                _ => unreachable!(),
            }

        }
    })
}



pub fn handle_session_query<M>(
    _api : &dyn Api,
    _storage: &dyn Storage,
    _env: &Env,
    query: SessionQueryMsg<M>,
) -> StdResult<Binary> 
    where M: QueryUsesActions
{
    match query {
        SessionQueryMsg::AllQueries {
            method
        } => {
            match method.unwrap_or_default() {
                AllQueryDerivation::Names => {
                    let vars = <M as IntoDiscriminant>
                        ::Discriminant::VARIANTS
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<String>>();
                    to_json_binary(&vars)
                }

                AllQueryDerivation::Strings => {
                    let vars = M::VARIANTS
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<String>>();
                    to_json_binary(&vars)
                }
            }
        },

        SessionQueryMsg::AllActions {
            method
        } => {

            match method.unwrap_or_default() {
                AllQueryDerivation::Names => {
                     let vars = <<M as QueryUsesActions>
                        ::ActionMsg as IntoDiscriminant>
                        ::Discriminant::VARIANTS
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<String>>();

                    to_json_binary(&vars)
                }

                AllQueryDerivation::Strings => {
                    let vars = <<M as QueryUsesActions>
                        ::ActionMsg>::VARIANTS  
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<String>>();

                    to_json_binary(&vars)
                   
                }
            }
        }

        SessionQueryMsg::Derive { 
            message, 
            method 
        } => {
            let act = Action::new(&message, method.unwrap_or_default())
                .map_err(|e| 
                    StdError::generic_err(format!("Failed to derive message: {}", e)
                ))?;

            to_json_binary(&act.result)
        }
    }
}
