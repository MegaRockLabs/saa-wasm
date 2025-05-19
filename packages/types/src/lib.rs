pub mod errors;
pub mod stores;

pub use smart_account_auth::{Expiration, CredentialData, cosmwasm_std, traits, ensure};
pub use smart_account_auth::{Credential, CredentialId, CredentialName, CredentialInfo, CredentialRecord};
pub use smart_account_auth::msgs::{MsgDataToSign, MsgDataToVerify, SignedDataMsg, AuthPayload};
pub use saa_schema::{saa_type, saa_error, serde, thiserror, schemars, strum, strum_macros};


#[cfg(feature = "session")]
mod sessions;
#[cfg(feature = "session")]
pub use {
    protos::{session_action, session_query},
    smart_account_auth::{Session, SessionInfo},
    sessions::*
};



#[saa_type]
pub struct StoredCredentials {
    /// whether there are stored native credentials that don't require a signature
    pub has_natives     :   bool,

    /// Default ID used for verification
    pub verifying_id    :   CredentialId,

     /// ID and info about every stored credential
    pub records         :   Vec<CredentialRecord>,

    // Nonce or account number used for replay attack protection
    pub account_number  :   u64,

    // Session keys that can be used used for specific actions
    //#[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "session")]
    pub sessions        :   Option<CredentialId>,
}



#[saa_type]
pub enum UpdateOperation<D : serde::Serialize = CredentialData> {
    Add(D),
    Remove(Vec<crate::CredentialId>),
}

