#![cfg_attr(not(target_env = "sgx"), no_std)]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sibyl_base_data_connector;
// extern crate serde_json;

pub mod github;
