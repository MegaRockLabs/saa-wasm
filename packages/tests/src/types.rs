use saa_schema::saa_derivable;
use types::wasm::{CosmosMsg, Coin};
use saa_wasm::{session_action, session_query};


#[saa_derivable]
pub enum ActionMsg {
    Execute { 
        msgs: Vec<CosmosMsg> 
    },

    #[strum(to_string = "{{ \"mint_token\": {{ \"minter\": \"{minter}\" }} }}")]
    MintToken {
        minter: String,
        msg: Option<CosmosMsg>
    },

    #[strum(to_string = "{{\"transfer_token\":{{\"id\":\"{id}\",\"to\":\"{to}\"}}}}")]
    TransferToken {
        id: String,
        to: String,
    },


    #[strum(to_string = "freeeeeze")]
    Freeze {},

    
    Purge {},
}



#[session_action(ActionMsg)]
#[saa_derivable]
pub enum ExecuteMsg {
    Execute { 
        msgs: Vec<CosmosMsg> 
    },
}



#[session_query(ExecuteMsg)]
#[saa_derivable]
pub enum QueryMsg {

    #[returns(Vec<Coin>)]
    GetBalance {},

    #[returns(String)]
    REAllyLongAnnoyingQuery(String),


    #[returns(Option<String>)]
    StrumQuery {
        #[strum(to_string = "{{ \"get_balance\": {{ \"address\": \"{address}\" }} }}")]
        address: String,
    },
}
