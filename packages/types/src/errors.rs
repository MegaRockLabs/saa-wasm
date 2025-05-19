
#[cfg(feature = "session")]
pub use smart_account_auth::SessionError;
pub use smart_account_auth::ReplayError;
pub use smart_account_auth::StorageError;
pub use smart_account_auth::AuthError;



/* #[saa_error]
pub enum SessionError {
    #[error("The session key has already expired")]
    Expired,

    #[error("No session key found")]
    NotFound,

    #[error("Only the owner or session key granter can perform this operation")]
    NotOwner,

    #[error("This session key wasn't granted to the given grantee")]
    NotGrantee,

    #[error("Must have both id and name specified")]
    InvalidGrantee,

    #[error("Invalid data or indifferent from the grantee")]
    InvalidGranter,

    #[error("Passed a list with no actions. Use AllowedActions::All() if you want to allow all of them")]
    EmptyCreateActions,

    #[error("No actions passed to execute")]
    EmptyPassedActions,

    #[error("Couldn't derivate a String result from given message and method")]
    DerivationError,

    #[error("Invalid actions provided. Check that there are no empty results not dublicates")]
    InvalidActions,

    #[error("Session creation messages aren't allowed to be in allowed message list")]
    InnerSessionAction,

    #[error("Current item cant't be used with the given session key")]
    NotAllowedAction,
}
 */

/* #[saa_error]
pub enum ReplayError {
    #[error("{0} is invalid as nonce. Expected: {1}")]
    DifferentNonce(u64, u64),

    #[error("The provided credential was meant for a different chain")]
    ChainIdMismatch,

    #[error("The provided credential was meant for a different contract address")]
    ContractMismatch,

    #[error("Error converting binary to {0}")]
    Convertation(String),
}
 */







/* #[saa_error]
pub enum AuthError {

    #[error("No credentials provided or credentials are partially missing")]
    NoCredentials,

    #[error("{0}")]
    MissingData(String),

    #[error("Invalid length of {0}.  Expected: {1};  Received: {2}")]
    InvalidLength(String, u16, u16),

    #[error("Values of v other than 27 and 28 not supported. Replay protection (EIP-155) cannot be used here.")]
    RecoveryParam,
    
    #[error("Error recovering from the signature: Addresses do not match")]
    RecoveryMismatch,

    #[error("The signed data is expected to be a replay attach protection envelope")]
    InvalidSignedData,

    #[error("Passkey challenge must be base64url to base64 encoded string")]
    PasskeyChallenge,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("{0}")]
    Signature(String),

    #[error("{0}")]
    Recovery(String),

    #[error("{0}")]
    Generic(String),

    #[error("{0}")]
    Crypto(String),

    #[error("Error converting binary to {0}")]
    Convertation(String),
    
    #[error("Semver parsing error: {0}")]
    SemVer(String),

    #[error("{0}")]
    SAAAuthError(#[from] SAAAuthError),

    #[error("Std: {0}")]
    StdError(#[from] StdError),
    
    #[error("Replay Protection Error: {0}")]
    Replay(#[from] ReplayError),

    #[error("{0}")]
    Storage(#[from] StorageError),

    #[cfg(feature = "session")]
    #[error("Session Error: {0}")]
    Session(#[from] SessionError),
}
 */



/* impl AuthError {
    pub fn generic<M: Into<String>>(msg: M) -> Self {
        AuthError::Generic(msg.into())
    }
}
 */