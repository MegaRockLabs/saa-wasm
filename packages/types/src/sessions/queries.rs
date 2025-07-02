use saa_schema::saa_type;
use saa_schema::strum::{IntoDiscriminant, VariantNames, VariantArray};
use saa_schema::strum_macros::{Display, EnumString, EnumDiscriminants};
use saa_schema::QueryResponses;
use smart_account_auth::cosmwasm_std::Binary;
use smart_account_auth::msgs::{Action, ActionDerivation, AllQueryDerivation};
use smart_account_auth::{SessionError, DerivableMsg};


#[saa_type]
#[derive(QueryResponses, EnumDiscriminants)]
#[strum_discriminants(
    name(SessionQueryName),
    derive(Display, EnumString),
    strum(serialize_all = "snake_case")
)]
pub enum SessionQueryMsg<M> 
where 
    M: QueryUsesActions,
    M::ActionMsg: IntoDiscriminant,
    <M::ActionMsg as IntoDiscriminant>::Discriminant: VariantArray + 'static,
{
    #[returns(Vec<String>)]
    AllQueries {
        method: Option<AllQueryDerivation>,
    },

    #[returns(Vec<String>)]
    AllActions {
        method: Option<AllQueryDerivation>,
    },
    
    #[returns(String)]
    Derive {
        message: M::ActionMsg,
        method: Option<ActionDerivation>,
    },

}


pub trait QueryUsesActions
where
    Self : DerivableMsg + VariantNames + IntoDiscriminant<Discriminant: VariantArray + 'static>,
    Self::ActionMsg :  DerivableMsg + saa_schema::schemars::JsonSchema +
         VariantNames + IntoDiscriminant<Discriminant: VariantArray + 'static>,
{
    type ActionMsg;
}


pub trait SessionQueriesMatch : QueryUsesActions
where
    <<Self as QueryUsesActions>::ActionMsg as IntoDiscriminant>::Discriminant: 'static,
{
    fn match_queries(&self) -> Option<SessionQueryMsg<Self>> 
    where <<Self as QueryUsesActions>::ActionMsg as IntoDiscriminant>::Discriminant: VariantArray;

}


#[saa_type]
pub struct QueryResTemplate {
    pub data: Option<Binary>,
    pub error: Option<String>,
}




#[saa_type]
pub struct  MsgToDerive<M : DerivableMsg> {
    pub message : M,
    pub method  : Option<ActionDerivation>,
}


impl<M : DerivableMsg> TryInto<Action> for MsgToDerive<M> {
    type Error = SessionError;
    fn try_into(self) -> Result<Action, Self::Error> {
        Action::new(&self.message, self.method.unwrap_or_default())
    }
}
