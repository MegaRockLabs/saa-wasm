use smart_account_auth::{
    msgs::{Action, AllQueryDerivation, DerivableMsg, SignedDataMsg, MsgDataToSign},
    Caller, Credential, CredentialName, Session, ensure,
    traits::Verifiable, 
};
use types::{
    sessions::{
        queries::{QueryUsesActions, SessionQueriesMatch, SessionQueryMsg},
        actions::{SessionActionMsg, SessionActionsMatch, ActionMsg},
    },
    wasm::{to_json_binary, Api, Binary, Env, MessageInfo, StdError, Storage},
    errors::{AuthError, SessionError, StorageError},
    stores::{map_get, map_save, map_remove, SESSIONS},
    strum::{IntoDiscriminant, VariantArray, VariantNames},
    serde
};
use crate::utils::{session_cred_from_signed};



#[cfg(feature = "multimsg")]
type ReturnMsg<D> = Vec<D>;
#[cfg(not(feature = "multimsg"))]
type ReturnMsg<D> = Option<D>;

type VerifyResult<D> = Result<ReturnMsg<D>, AuthError>;

fn default_return_msg<D>() -> ReturnMsg<D> {
    #[cfg(feature = "multimsg")]
    {
        vec![]
    }
    #[cfg(not(feature = "multimsg"))]
    {
        None
    }
}

fn wrap_one_rmsg<D>(msg: D) -> ReturnMsg<D> {
    #[cfg(feature = "multimsg")]
    {
        vec![msg]
    }
    #[cfg(not(feature = "multimsg"))]
    {
        Some(msg)
    }
}


fn verify_common<D: DerivableMsg>(
    session: &Session,
    cred    : &Credential,
    msgs    : Vec<D> 
) -> VerifyResult<D> {
    let (id, info) = session.grantee.clone();
    ensure!(info.name == CredentialName::Native, SessionError::InvalidGrantee);
    ensure!(id == cred.id(), SessionError::NotGrantee);
    #[cfg(feature = "multimsg")]
    {
        ensure!(msgs.iter().all(|m| session.can_do_msg(m)), SessionError::NotAllowedAction);
        return Ok(msgs)
    }
    #[cfg(not(feature = "multimsg"))]
    {
        ensure!(msgs.len() == 1, SessionError::InvalidActions);
        let msg = msgs[0].clone();
        ensure!(session.can_do_msg(&msg), SessionError::NotAllowedAction);
        return Ok(Some(msg))
    }
}


pub fn verify_session_native<D : DerivableMsg>(
    api: &dyn Api,
    address: &str,
    session: &Session,
    msg: D
) -> VerifyResult<D> {
    let cred = Caller::from(address);
    cred.verify_cosmwasm(api)?;
    verify_common( &session, &cred.into(), vec![msg])
}



pub fn verify_session_signed<T : serde::de::DeserializeOwned + DerivableMsg>(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    key: &String,
    session: &Session,
    msg: SignedDataMsg
) -> VerifyResult<T> {

    let signed : MsgDataToSign<T> = crate::utils::convert_validate_return(
        msg.data.as_slice(), 
        env, 
        session.nonce
    )?;
    let cred = session_cred_from_signed(api, storage,  key, msg)?;
    
    let res = verify_common(&session, &cred, signed.messages)?;
    
    map_save(storage, &SESSIONS, key, &Session {
        nonce: session.nonce + 1,
        ..session.clone()
    }, "session key")?;

    Ok(res)
}


pub fn update_session(
    storage: &mut dyn Storage,
    key: &String,
    session: &Session,
) -> Result<(), StorageError> {
    let session = match map_get(storage, &SESSIONS, key, "session key") {
        Ok(loaded) => &Session { nonce: loaded.nonce + 1, ..session.clone() },
        Err(_) => session,
    };
    map_save(storage, &SESSIONS, &key, session, "session key")
}




pub fn handle_session_actions<M>(
    api : &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    msg: M,
    admin: Option<String>,
) -> Result<(Option<Session>, ReturnMsg<M>), AuthError> 
    where M : serde::de::DeserializeOwned + SessionActionsMatch,
{

    let session_msg = match msg.match_actions() {
        Some(msg) => msg,
        None => return Ok((None, wrap_one_rmsg(msg))),
    };

    let addr = admin.unwrap_or(info.sender.to_string());
       
    match session_msg {
        SessionActionMsg::CreateSession(
            mut create
        ) => {
            // set sender as granter
            create.session_info.granter = Some(addr);
            let session = create.to_session(&env)?;
            let key = session.key();
            update_session(storage,  &key, &session)?;
            return Ok((Some(session), default_return_msg()));
        },

        SessionActionMsg::CreateSessionFromMsg(
            mut create
        ) => {
            // set sender as granter
            create.session_info.granter = Some(addr);
            let session = create.to_session(&env)?;
            let key = session.key();
            update_session(storage,  &key, &session)?;
            return Ok((Some(session), wrap_one_rmsg(create.message.clone())));
        },

        SessionActionMsg::WithSessionKey(with_msg) => {
            let key = &with_msg.session_key;
            let session = map_get(storage, &SESSIONS, key, "session key")?;
            if session.expiration.is_expired(&env.block) {
                map_remove(storage, &SESSIONS, key);
                return Err(SessionError::Expired.into())
            }
            let msgs   = match with_msg.message {

                ActionMsg::Signed(msg) => {
                    verify_session_signed(api, storage, env, key, &session, msg)?
                }
                ActionMsg::Native(execute) => {
                    verify_session_native(api,  addr.as_str(), &session, execute)?
                },
            };
            Ok((Some(session), msgs))
        },

        SessionActionMsg::RevokeSession(msg) => {
            let key = &msg.session_key;
            if let Ok(loaded) = map_get(storage, &SESSIONS, key, "session key") {
                // anyone can revoke the expired session
                if !loaded.expiration.is_expired(&env.block) {
                    ensure!(loaded.granter == addr, SessionError::NotOwner);
                }
                map_remove(storage, &SESSIONS, key);
                Ok((None, default_return_msg()))
            } else {
                return Err(SessionError::NotFound.into())
            }            
        },
    }
    
}




pub fn handle_session_queries<M>(
    _api : &dyn Api,
    _storage: &dyn Storage,
    _env: &Env,
    msg: &M,
) -> Result<Option<Binary>, StdError> 
where
    M: SessionQueriesMatch,
    <M::ActionMsg as IntoDiscriminant>::Discriminant: VariantArray + 'static,
{
    
    let session_query = match msg.match_queries() {
        Some(msg) => msg,
        None => return Ok(None),
    };

    return Ok(Some(match session_query {
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
                    to_json_binary(&vars)?
                }

                AllQueryDerivation::Strings => {
                    let vars = M::VARIANTS
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<String>>();
                    to_json_binary(&vars)?
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

                    to_json_binary(&vars)?
                }

                AllQueryDerivation::Strings => {
                    let vars = <<M as QueryUsesActions>
                        ::ActionMsg>::VARIANTS  
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<String>>();

                    to_json_binary(&vars)?
                   
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

            to_json_binary(&act.result)?
        }
    }));
}

