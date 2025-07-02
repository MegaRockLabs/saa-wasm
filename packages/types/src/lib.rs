#[cfg(feature = "session")]
pub mod sessions;
pub mod stores;

pub use smart_account_auth::errors;
pub use smart_account_auth::cosmwasm_std as wasm;
pub use saa_schema::{saa_type, serde, strum, strum_macros};


#[cfg(feature = "session")]
pub mod macros {
    pub use protos::{session_action, session_query};
}


use smart_account_auth::{CredentialId, CredentialRecord, CredentialData};


#[saa_type]
pub enum UpdateOperation<D : serde::Serialize = CredentialData> {
    Add(D),
    Remove(Vec<crate::CredentialId>),
}




#[saa_type]
pub struct StoredCredentials {
    /// whether there are stored native credentials that don't require a signature
    pub has_natives     :   bool,

    /// Default ID used for verification
    pub primary_id      :   CredentialId,

     /// ID and info about every stored credential
    pub records         :   Vec<CredentialRecord>,

    // Nonce or account number used for replay attack protection
    pub account_number  :   u64,

    // Session keys that can be used used for specific actions
    #[cfg(feature = "session")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sessions        :   Vec<(String, smart_account_auth::Session)>,
}
