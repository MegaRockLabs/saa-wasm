use std::str::FromStr;

use actions::SessionActionName;
use saa_schema::saa_type;
use smart_account_auth::{cosmwasm_std::Env, ensure, msgs::{AllowedActions, ActionDerivation}, CredentialId, CredentialRecord, Expiration};
use strum::IntoEnumIterator;
use crate::errors::SessionError;


pub mod queries;
pub mod actions;

type GranteeInfo = CredentialRecord;

#[saa_type]
pub struct SessionInfo  {
    pub grantee     :       GranteeInfo,
    pub granter     :       Option<CredentialId>,
    pub expiration  :       Option<Expiration>,
}




impl SessionInfo {
    pub fn checked_params(
        &self, 
        env: &Env,
        actions: Option<&AllowedActions>
    ) -> Result<(CredentialId, CredentialRecord, Expiration, AllowedActions), SessionError> {
        let granter = self.granter.clone().unwrap_or_default();
        let (id, info) = self.grantee.clone();
        ensure!(!id.is_empty(), SessionError::InvalidGrantee);
        let expiration = self.expiration.clone().unwrap_or_default();
        ensure!(!expiration.is_expired(&env.block), SessionError::Expired);
        if let Some(granter) = &self.granter {
            ensure!(!granter.is_empty() && *granter != id, SessionError::InvalidGranter);
        }
        let actions : AllowedActions = match actions {
            Some(actions) => {
                if let AllowedActions::Include(ref actions) = actions {
                    ensure!(actions.len() > 0, SessionError::EmptyCreateActions);

                    let validity_ok = actions
                        .iter()
                        .enumerate()
                        .all(|(i, action)| {
                            let ok = !action.result.is_empty() 
                                &&  actions
                                    .into_iter()
                                    .skip(i + 1)
                                    .filter(|action2| action == *action2)
                                    .count() == 0;
                            ok
                        });
                    ensure!(validity_ok, SessionError::InvalidActions);

                    let no_inner_sessions = actions
                        .iter()
                        .all(|action| {
                            match action.method {
                                ActionDerivation::Json => !action.result.contains("\"session_actions\"") &&
                                                            !action.result.contains("\"session_info\""),
                                                            
                                _ => !is_session_action_name(action.result.as_str())
                                
                            }
                        });

                    ensure!(no_inner_sessions, SessionError::InnerSessionAction);
                }
                actions.clone()
            },
            None => AllowedActions::All {},
        };
        Ok((granter, (id, info), expiration, actions))
    }
}



pub(crate) fn is_session_action_name(name: &str) -> bool {
    SessionActionName::iter()
        .any(|action| {
            if action.as_ref() == name {
                return true;
            }
            if let Ok(act) = SessionActionName::from_str(name) {
                return action == act;
            }
            false
        })
}
