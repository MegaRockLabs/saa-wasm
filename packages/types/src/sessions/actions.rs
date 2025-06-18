
use saa_schema::saa_type;
use saa_schema::strum_macros::Display;
use smart_account_auth::cosmwasm_std::Env;
use smart_account_auth::{Session, SessionInfo, DerivableMsg};
use smart_account_auth::msgs::{SignedDataMsg, Action, AllowedActions, ActionDerivation};
use crate::{errors::SessionError};

#[cfg(not(feature = "multi"))]
pub type MsgArg<D> = D;
#[cfg(feature = "multi")]
pub type MsgArg<D> = Vec<D>;



#[saa_type]
pub struct CreateSession {
    pub allowed_actions     :      AllowedActions,
    pub session_info        :      SessionInfo,
}



#[saa_type]
pub struct CreateSessionFrom<M : DerivableMsg> {
    pub msgs                :      M,
    pub derivation          :      Option<ActionDerivation>,
    pub session_info        :      SessionInfo,
}




#[saa_type]
pub struct WithSessionMsg<M> {
    pub msgs                :      MsgArg<M>,
    pub session_key         :      String,
}


#[saa_type]
pub struct RevokeKeyMsg {
    pub session_key         :      String,
}




#[saa_type]
#[derive(Display)]
pub enum SessionActionMsg<M : DerivableMsg> {
    CreateSession(CreateSession),
    CreateSessionFromMsg(CreateSessionFrom<M>),
    WithSessionKey(WithSessionMsg<M>),
    RevokeSession(RevokeKeyMsg),
}


#[saa_type]
pub struct  SessionAction<M : DerivableMsg> {
    pub msg          :      SessionActionMsg<M>,
    pub signed       :      Option<SignedDataMsg>,
}




impl CreateSession {
    pub fn to_session(
        &self, 
        env: &Env
    ) -> Result<Session, SessionError> {
        
        let (
            granter,
            grantee, 
            expiration, 
            actions
        ) = self.session_info.checked_params(env, Some(&self.allowed_actions))?;

        Ok(Session {
            actions,
            expiration,
            grantee,
            granter,
            nonce: 0,
        })
    }
}



impl<M: DerivableMsg> CreateSessionFrom<M> {

    pub fn to_session(
        &self, 
        env: &Env
    ) -> Result<Session, SessionError> {
        let (
            granter, 
            grantee, 
            expiration, 
            _
        ) = self.session_info.checked_params(env, None)?;
        
        let method = self.derivation.clone().unwrap_or_default();
        let action = Action::new(&self.msgs, method)
            .map_err(|_| SessionError::InvalidActions)?;

        Ok(Session {
            actions: AllowedActions::Include(vec![action]),
            expiration,
            grantee,
            granter,
            nonce: 0,
        })
    }
}

