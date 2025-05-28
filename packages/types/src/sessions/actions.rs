
use saa_schema::saa_type;
use smart_account_auth::cosmwasm_std::Env;
use smart_account_auth::{Session, SessionInfo};
use smart_account_auth::{msgs::DerivableMsg};
use smart_account_auth::msgs::{SignedDataMsg, Action, AllowedActions, ActionDerivation};
use crate::{errors::SessionError};



#[saa_type]
pub enum ActionMsg<M> {
    Native(M),
    Signed(SignedDataMsg)
}



#[saa_type]
pub struct CreateSession {
    pub allowed_actions     :      AllowedActions,
    pub session_info        :      SessionInfo,
}



#[saa_type]
pub struct CreateSessionFromMsg<M : DerivableMsg> {
    pub message             :      M,
    pub derivation          :      Option<ActionDerivation>,
    pub session_info        :      SessionInfo,
}




#[saa_type]
pub struct WithSessionMsg<M> {
    pub message             :      ActionMsg<M>,
    pub session_key         :      String,
}


#[saa_type]
pub struct RevokeKeyMsg {
    pub session_key         :      String,
}




#[saa_type]
pub enum SessionActionMsg<M : DerivableMsg> {
    CreateSession(CreateSession),
    CreateSessionFromMsg(CreateSessionFromMsg<M>),
    WithSessionKey(WithSessionMsg<M>),
    RevokeSession(RevokeKeyMsg),
}




pub trait SessionActionsMatch<M : DerivableMsg> : Into<M>  {
    fn match_actions(&self) -> Option<SessionActionMsg<M>>;
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



impl<M: DerivableMsg> CreateSessionFromMsg<M> {

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
        let action = Action::new(&self.message, method)
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

