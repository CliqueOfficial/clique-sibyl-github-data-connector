#![cfg_attr(not(target_env = "sgx"), no_std)]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sibyl_base_data_connector;
// extern crate serde_json;
extern crate multihash;
extern crate hex;
extern crate rsa;
extern crate once_cell;
extern crate rand;

pub mod github;
