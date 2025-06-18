use types::{errors::CredentialError, wasm::{DepsMut, Storage}};
use saa_wasm::{credential_count, get_stored_credentials, 
    reset_credentials, save_credentials, update_credentials
};

use crate::utils::{
    base_credentials, get_cosmos_arbitrary, get_eth_personal, get_mock_deps, get_mock_env, get_passkey, person_info, ALICE_ADDR, BOB_ADDR, MESSAGE_TEXT, SIGN_NONCE
};

use smart_account_auth::{
    errors::StorageError, AuthError, Caller, CheckOption, Credential, CredentialData, CredentialId, CredentialInfo, CredentialName, CredentialsWrapper, ReplayParams, Verifiable
};

use types::{
    stores::{ACCOUNT_NUMBER, CREDENTIAL_INFOS, HAS_NATIVES, PRIMARY_ID},
    UpdateOperation
};


fn checked_remaining(
    storage: &mut dyn Storage,
    remaining: Vec<(CredentialId, CredentialInfo)>,
    check_verifying: bool,
    check_natives: bool,
    verifying_id: Option<CredentialId>,
) -> Result<(), StorageError> {
    if remaining.is_empty() {
        if check_verifying {
            PRIMARY_ID.remove(storage);
        }
        if check_natives {
            HAS_NATIVES.save(storage, &false)?;
        }
        return Ok(());
    }
    
    if check_verifying {
        let id = verifying_id.unwrap_or(remaining[0].0.clone());
        PRIMARY_ID.save(storage, &id)?;
    }

    if check_natives {
        let has: bool = remaining.iter().any(|(_, info)| info.name ==  CredentialName::Native);
        HAS_NATIVES.save(storage, &has)?;
    }
    Ok(())
}


fn remove_credential_smart(
    storage: &mut dyn Storage,
    id: &CredentialId,
) -> Result<(), StorageError> {
    remove_credential(storage, id).map_err(|_| StorageError::NotFound)?;
    let remaining = get_stored_credentials(storage)?.records;
    let check_ver = PRIMARY_ID.load(storage)
        .map_err(|_| StorageError::NotFound)
        ? == *id;

    checked_remaining(
        storage, 
        remaining, 
        check_ver,
        true, 
        None
    )
}



#[test]
fn credential_crds_work() {
    let mut mocks = get_mock_deps();
    let mut deps = mocks.as_mut();

    let eth_cred : Credential = get_eth_personal().into();
    let cosmos_cred : Credential = get_cosmos_arbitrary().into();
    let passkey_cred : Credential = get_passkey().into();

    // Saving credentials
    save_credential(&mut deps, &eth_cred.id(), &eth_cred).unwrap();
    save_credential(&mut deps, &cosmos_cred.id(), &cosmos_cred).unwrap();
    save_credential(&mut deps, &passkey_cred.id(), &passkey_cred).unwrap();

    PRIMARY_ID.save(deps.storage, &eth_cred.id()).unwrap();

    assert_eq!(credential_count(deps.storage), 3);

    // remove simple
    remove_credential(deps.storage, &cosmos_cred.id()).unwrap();
    assert_eq!(credential_count(deps.storage), 2);
    
    // remove smart veryfying
    remove_credential_smart(deps.storage, &eth_cred.id()).unwrap();
    assert_eq!(credential_count(deps.storage), 1);
    // moved forward to the next one
    assert_eq!(PRIMARY_ID.load(deps.storage).unwrap(), passkey_cred.id());
    
    // remove all
    reset_credentials(deps.storage, true, true).unwrap();
    assert_eq!(credential_count(deps.storage), 0);

    let native : Credential = Caller::from(ALICE_ADDR).into();

    // Saving again but now with caller
    save_credential(&mut deps, &eth_cred.id(), &eth_cred).unwrap();
    save_credential(&mut deps, &cosmos_cred.id(), &cosmos_cred).unwrap();
    save_credential(&mut deps, &passkey_cred.id(), &passkey_cred).unwrap();
    save_credential(&mut deps, &native.id(), &native).unwrap();

    let storage = deps.storage;
    PRIMARY_ID.save(storage, &native.id()).unwrap();
    HAS_NATIVES.save(storage, &true).unwrap();

    // none of the two should change
    remove_credential_smart(storage, &passkey_cred.id()).unwrap();
    assert_eq!(PRIMARY_ID.load(storage).unwrap(), native.id());
    assert_eq!(HAS_NATIVES.load(storage).unwrap(), true);

    remove_credential_smart(storage, &native.id()).unwrap();
    assert_eq!(PRIMARY_ID.load(storage).unwrap(), eth_cred.id());
    assert_eq!(HAS_NATIVES.load(storage).unwrap(), false);
    assert_eq!(credential_count(storage), 2);
}



fn save_credential(deps: &mut DepsMut, id: &str, cred: &Credential) 
    -> Result<(), AuthError> {
    let info = cred.verify(deps.as_ref())?;
    CREDENTIAL_INFOS.save(deps.storage, id.to_string(), &info)
        .map_err(|e| StorageError::Write("credential".into(), e.to_string()).into())    
}


fn remove_credential(storage: &mut dyn Storage, id: &str) -> Result<(), AuthError> {
    CREDENTIAL_INFOS.remove(storage, id.to_string());
    Ok(())
}



#[test]
fn save_credential_data_work() {
    let mut mocks = get_mock_deps();
    let deps = mocks.as_mut();
    let env = get_mock_env();

    
    let bob = person_info(BOB_ADDR);
    
    let params = ReplayParams::new(SIGN_NONCE, CheckOption::Messages(vec![MESSAGE_TEXT.to_string()]));

    let data =   CredentialData::new(base_credentials(), None);
    let verified = data.verify(deps.as_ref(), &env, &bob, params).unwrap();

    save_credentials(deps.storage, &verified).unwrap();
    
    let storage = deps.storage;

    // asserted saved data is same as initial
    assert_eq!(verified.credentials.len(), data.credentials.len());
    assert_eq!(ACCOUNT_NUMBER.load(storage).unwrap_or_default(), 1);


    // All credentials are saved stored info matches
    for cred in verified.credentials.into_iter() {
        let info = CREDENTIAL_INFOS.load(storage, cred.0).unwrap();
        assert_eq!(info, cred.1);
    }

    // No extra credentials were saved
    assert_eq!(credential_count(storage), data.credentials.len());

    // Verifying credential id is stored properly
    let ver = PRIMARY_ID.load(storage).unwrap();
    let first = data.credentials.first().unwrap();
    assert!(first.id() == ver && data.primary_id() == ver);

    // should't have any natives callers
    assert!(!HAS_NATIVES.load(storage).unwrap_or(false));
}




#[test]
fn save_cred_data_with_native() {
    let mut mocks = get_mock_deps();
    let env = get_mock_env();
    
    let alice = person_info(ALICE_ADDR);
    
    let deps = mocks.as_mut();

    let base_creds = base_credentials();
    let base_count = base_creds.len();
    

    let params = ReplayParams::new(SIGN_NONCE, CheckOption::Messages(vec![MESSAGE_TEXT.to_string()]));


    let data =  CredentialData::new(base_creds, Some(true))
        .with_native(ALICE_ADDR)
        .verify(deps.as_ref(), &env, &alice, params.clone())
        .unwrap();
    
    // save credentials
    save_credentials(deps.storage, &data).unwrap();

    // extra Caller credential is saved
    assert_eq!(credential_count(deps.storage), base_count + 1);
    assert_eq!(data.credentials.last().unwrap().0, alice.sender.as_str());

    // should have natives callers
    assert!(HAS_NATIVES.load(deps.storage).unwrap_or(false));

    reset_credentials(deps.storage, true, true).unwrap();

    let data = CredentialData::new(vec![], Some(true))
        .with_native(ALICE_ADDR)
        .verify(deps.as_ref(), &env, &alice, params)
        .unwrap();

    save_credentials(deps.storage, &data).unwrap();

    let all = get_stored_credentials(deps.storage).unwrap().records;
    let (id, info) = all.first().unwrap();
    println!("id: {}, info: {:?}", id, info);
    println!("alice: {}", alice.sender.as_str());
    println!("data: {:?}", data);
    assert!(id == alice.sender.as_str());
    assert!(HAS_NATIVES.load(deps.storage).unwrap_or_default());
    assert_eq!(PRIMARY_ID.load(deps.storage).unwrap(), *id);
    assert_eq!(CredentialName::Native, info.name);
}






#[test]
fn update_cred_data_remove_simple() {
    let mut mocks = get_mock_deps();
    let deps = mocks.as_mut();
    
    let env = get_mock_env();
    let alice = person_info(ALICE_ADDR);

    let eth_cred : Credential = get_eth_personal().into();
    let cosmos_cred : Credential = get_cosmos_arbitrary().into();
    let passkey_cred : Credential = get_passkey().into();
    let alice_cred : Credential = Caller::from(alice.sender.as_str()).into();
    let params = ReplayParams::new(SIGN_NONCE, CheckOption::Messages(vec![MESSAGE_TEXT.to_string()]));

    let data= CredentialData::new(
        vec![passkey_cred.clone(), eth_cred.clone()], Some(true)
        )
        .verify(deps.as_ref(), &env, &alice, params)
        .unwrap();
       
    save_credentials(deps.storage, &data).unwrap();
    assert_eq!(credential_count(deps.storage), 3);
    
    // error due to invalid arguments
    let empty = UpdateOperation::Remove(vec![]);
    assert!(update_credentials(deps.storage, &empty).is_err());

    // ok but no change cause the id is not there
    let op = UpdateOperation::Remove(vec![cosmos_cred.id()]);
    assert!(update_credentials(deps.storage, &op).is_ok());

    // ok but removing verifying credential
    let op = UpdateOperation::Remove(vec![passkey_cred.id()]);
    assert!(update_credentials(deps.storage, &op).is_ok());

    
    assert!(credential_count(deps.storage) == 2);
    assert_eq!(PRIMARY_ID.load(deps.storage).unwrap(), eth_cred.id());

    // ok but same thing doesnt't do anything
    assert!(update_credentials(deps.storage, &op).is_ok());

    // ok but can't use alice anymore
    let op = UpdateOperation::Remove(vec![alice_cred.id()]);
    assert!(!HAS_NATIVES.load(deps.storage).unwrap());
    assert!(update_credentials(deps.storage, &op).is_ok());

    // should update has natives flag to false
    assert!(!HAS_NATIVES.load(deps.storage).unwrap());
    assert!(credential_count(deps.storage) == 1);

    // reset credentials
    reset_credentials(deps.storage, true, true).unwrap();
    save_credentials(deps.storage, &data).unwrap();

    // error: can't remove all three
    let op = UpdateOperation::Remove(vec![eth_cred.id(), passkey_cred.id(), alice_cred.id()]);
    assert!(update_credentials(deps.storage, &op).is_err());

    println!("Credential count: {}", credential_count(deps.storage));
    println!("Primary ID: {:?}", PRIMARY_ID.load(deps.storage));
    assert_eq!(credential_count(deps.storage), 3);
    assert_eq!(PRIMARY_ID.load(deps.storage).unwrap(), passkey_cred.id());
    assert!(!HAS_NATIVES.load(deps.storage).unwrap());

    // leave last one
    let op = UpdateOperation::Remove(vec![eth_cred.id(), passkey_cred.id()]);
    assert!(update_credentials(deps.storage, &op).is_ok());
    assert!(!HAS_NATIVES.load(deps.storage).unwrap());
    assert_eq!(PRIMARY_ID.load(deps.storage).unwrap(), alice_cred.id());
    assert_eq!(credential_count(deps.storage), 1);

    //assert!(update_credentials(api, storage, &env, &alice.sender.to_string(), op.clone()).is_err());
    let op = UpdateOperation::Remove(vec![alice_cred.id()]);
    let err = update_credentials(deps.storage, &op).unwrap_err();
    println!("Error: {}", err);
    assert_eq!(err, AuthError::Credential(CredentialError::NoneLeft))
}



