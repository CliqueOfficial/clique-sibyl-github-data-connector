use std::prelude::v1::*;
use sibyl_base_data_connector::base::DataConnector;
use sibyl_base_data_connector::errors::NetworkError;
use sibyl_base_data_connector::serde_json::json;
use std::string::ToString;
use sibyl_base_data_connector::serde_json::Value;
use std::{str, println};
use String;
use std::panic;
use sibyl_base_data_connector::utils::{parse_result, tls_post};
use sibyl_base_data_connector::utils::{simple_tls_client, simple_tls_client_no_cert_check};
use multihash::{Code, MultihashDigest};
use once_cell::sync::Lazy;
use std::sync::Arc;
use rsa::{RSAPrivateKey, PaddingScheme};

use crate::env;

static RSA_PRIVATE_KEY: Lazy<Arc<RSAPrivateKey>> = Lazy::new(|| {
    let seed = [0u8; 16];
    let mut rng = rand::rngs::mock::StepRng::new(0, 1);
    let bits = 2048;
    let key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    Arc::new(key)
});

pub struct GithubConnector {

}

impl DataConnector for GithubConnector {
    fn query(&self, query_type: &Value, query_param: &Value) -> Result<Value, NetworkError> {
        let query_type_str = match query_type.as_str() {
            Some(r) => r,
            _ => {
                let err = format!("query_type to str failed");
                println!("{:?}", err);
                return Err(NetworkError::String(err));
            }
        };
        match query_type_str {
            "github_get_rsa_public_key" => {
                let pub_key = Arc::clone(&*RSA_PRIVATE_KEY).to_public_key();
                Ok(json!(format!("{:?}", pub_key)))
            },
            "github_user_stats_zk_halo2" => {
                let mut secret = query_param["bearer"].as_str().unwrap_or("");
                let mut dec_data = vec![];
                let encrypted_secret_res = query_param["encryptedBearer"].as_str();
                if encrypted_secret_res.is_some() {
                    let encrypted_secret = base64::decode(encrypted_secret_res.unwrap());
                    if encrypted_secret.is_err() {
                        return Err(NetworkError::String("base64 decode github encryptedBearer failed!".to_string()));
                    }
                    let rsa_key = Arc::clone(&*RSA_PRIVATE_KEY);
                    let dec_data_res = rsa_key.decrypt(
                        PaddingScheme::PKCS1v15, &encrypted_secret.unwrap());
                    if dec_data_res.is_err() {
                        return Err(NetworkError::String("decrypt github Bearer failed!".to_string()));
                    }
                    dec_data = dec_data_res.unwrap();
                    let secret_res = std::str::from_utf8(&dec_data);
                    if secret_res.is_err() {
                        return Err(NetworkError::String("decrypt github Bearer failed!".to_string()));
                    }
                    secret = secret_res.unwrap();
                }
                let query_user = format!(
                    "GET {} HTTP/1.1\r\n\
                    HOST: {}\r\n\
                    Authorization: token {}\r\n\
                    User-Agent: curl/7.79.1\r\n\
                    Accept: application/json\r\n\r\n",
                    env::GITHUB_USER_SUFFIX,
                    env::GITHUB_API_HOST,
                    secret
                );
                let github_id_hash: String;
                let github_username: String;
                match simple_tls_client(env::GITHUB_API_HOST, &query_user, 443) {
                    Ok(r) => {
                        let github_id: i64 = match r["id"].as_i64() {
                            Some(id) => id,
                            _ => {
                                return Err(NetworkError::String("user id not found when query github user by token".to_string()));
                            }
                        };
                        let mut github_id_hex = format!("{:02x}", github_id);
                        let mut github_id_hex_len = github_id_hex.len() / 2;
                        if github_id_hex.len() % 2 == 1 {
                            github_id_hex_len += 1;
                            // for length of github_id_hex is odd, pad a prefix of zero
                            github_id_hex = format!("0{}", github_id_hex);
                        }
                        let mut github_id_hex_bytes = vec![0u8; github_id_hex_len];
                        match hex::decode_to_slice(github_id_hex, &mut github_id_hex_bytes) {
                            Ok(_) => (),
                            Err(e) => {
                                return Err(NetworkError::String(format!("err when decode_to_slice: {:?}", e)));
                            }
                        }
                        let mut hash = [0u8; 64];
                        match hex::encode_to_slice(&Code::Keccak256.digest(&github_id_hex_bytes).digest(), &mut hash) {
                            Ok(_) => (),
                            Err(e) => {
                                return Err(NetworkError::String(format!("err when encode_to_slice: {:?}", e)));
                            }
                        }
                        github_id_hash = match str::from_utf8(&hash) {
                            Ok(r) => format!("0x{}", r),
                            Err(e) => {
                                return Err(NetworkError::String(format!("err when from_utf8 for github_id_hash: {:?}", e)));
                            }
                        };
                        github_username = match r["result"]["login"].as_str() {
                            Some(name) => name.to_string(),
                            _ => {
                                return Err(NetworkError::String("login name not found when query github user by token".to_string()));
                            }
                        }
                    },
                    Err(e) => {
                        return Err(e);
                    }
                }
                let query = format!(
                    "{{ \"query\": \"query {{ user(login: \\\"{}\\\") {{ name login contributionsCollection \
                     {{ totalCommitContributions restrictedContributionsCount }} repositoriesContributedTo( \
                     first: 1 contributionTypes: [COMMIT, ISSUE, PULL_REQUEST, REPOSITORY]) {{ totalCount }} \
                     pullRequests(first: 1) {{ totalCount }} openIssues: issues(states: OPEN) {{ totalCount }} \
                     closedIssues: issues(states: CLOSED) {{ totalCount }} followers {{ totalCount }} repositories\
                     ( first: 100 ownerAffiliations: OWNER orderBy: {{direction: DESC, field: STARGAZERS}}) {{ \
                     totalCount nodes {{ stargazers {{ totalCount }} }} }} }} }}\" }}",
                    github_username
                );
                let req = format!(
                    "POST {} HTTP/1.1\r\n\
                    HOST: {}\r\n\
                    Authorization: bearer {}\r\n\
                    User-Agent: curl/7.79.1\r\n\
                    Accept: */*\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: {}\r\n\r\n\
                    {}",
                    env::GITHUB_GRAPHQL_SUFFIX,
                    env::GITHUB_API_HOST,
                    secret,
                    query.len(),
                    query
                );
                let plaintext = match tls_post(env::GITHUB_API_HOST, &req, 443) {
                    Ok(r) => r,
                    Err(e) => {
                        let err = format!("tls_post to str: {:?}", e);
                        println!("{:?}", err);
                        return Err(NetworkError::String(err));
                    }
                };
                match parse_result(env::GITHUB_API_HOST, &plaintext) {
                    Ok(resp_json) => {
                         match panic::catch_unwind(|| {
                            if let Some(errors) = resp_json.pointer("/errors") {
                                panic!("errors from github api: {}", errors.to_string());
                            }
                            let zero_value = json!(0i64);
                            let followers: i64 = resp_json.pointer(
                                "/data/user/followers/totalCount"
                            ).unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            let empty_list_value = json!([]);
                            let repos: &Value = resp_json.pointer(
                                "/data/user/repositories/nodes"
                            ).unwrap_or(&empty_list_value);
                            let mut total_stars: i64 = 0;
                            for repo in repos.as_array().unwrap_or(&empty_list_value.as_array().unwrap()) {
                                total_stars += repo.pointer("/stargazers/totalCount").unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            }
                            let total_commits: i64 = resp_json.pointer(
                                "/data/user/contributionsCollection/totalCommitContributions"
                            ).unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            let total_prs: i64 = resp_json.pointer(
                                "/data/user/pullRequests/totalCount"
                            ).unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            let contributed_to: i64 = resp_json.pointer(
                                "/data/user/repositoriesContributedTo/totalCount"
                            ).unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            let total_open_issues: &Value = resp_json.pointer("/data/user/openIssues/totalCount").unwrap_or(&zero_value);
                            let total_closed_issues: &Value = resp_json.pointer("/data/user/closedIssues/totalCount").unwrap_or(&zero_value);
                            let total_issues: i64 = total_open_issues.as_i64().unwrap_or(0) + total_closed_issues.as_i64().unwrap_or(0);

                            let data_slot = query_param["dataSlot"].as_i64().unwrap_or(0i64) as usize;
                            let values = [
                                followers,
                                total_stars,
                                total_commits,
                                total_prs,
                                contributed_to,
                                total_issues,
                            ];
                            let req = format!(
                                "GET /zkRangeProof?data0={}&data1={}&data2={}&data3={}&data4={}&data5={}&data_slot={} HTTP/1.1\r\n\
                                HOST: {}\r\n\
                                User-Agent: curl/7.79.1\r\n\
                                Accept: */*\r\n\r\n",
                                values[0],
                                values[1],
                                values[2],
                                values[3],
                                values[4],
                                values[5],
                                data_slot,
                                env::SIGN_CLAIM_SGX_HOST
                            );
                            let empty_arr: Vec<Value> = vec![];
                            let zk_range_proof = simple_tls_client_no_cert_check(env::SIGN_CLAIM_SGX_HOST, &req, 12341).unwrap_or(json!({"result": {}}));
                            let zk: &Value = &zk_range_proof["result"];
                            json!({
                                "userIdHash": github_id_hash,
                                "zkProof": zk["proof"].as_array().unwrap_or(&empty_arr),
                                "innerAttestation": zk["attestation"].as_str().unwrap_or("")
                            })
                        }) {
                            Ok(r) => Ok(r),
                            Err(e) => {
                                let err = format!("github user stats failed: {:?}", e);
                                println!("{:?}", err);
                                Err(NetworkError::String(err))
                            }
                        }
                    },
                    Err(e) => {
                        Err(e)
                    }
                }
            },
            "github_user_stats_zk_claim" => {
                let mut secret = query_param["bearer"].as_str().unwrap_or("");
                let mut dec_data = vec![];
                let encrypted_secret_res = query_param["encryptedBearer"].as_str();
                if encrypted_secret_res.is_some() {
                    let encrypted_secret = base64::decode(encrypted_secret_res.unwrap());
                    if encrypted_secret.is_err() {
                        return Err(NetworkError::String("base64 decode github encryptedBearer failed!".to_string()));
                    }
                    let rsa_key = Arc::clone(&*RSA_PRIVATE_KEY);
                    let dec_data_res = rsa_key.decrypt(
                        PaddingScheme::PKCS1v15, &encrypted_secret.unwrap());
                    if dec_data_res.is_err() {
                        return Err(NetworkError::String("decrypt github Bearer failed!".to_string()));
                    }
                    dec_data = dec_data_res.unwrap();
                    let secret_res = std::str::from_utf8(&dec_data);
                    if secret_res.is_err() {
                        return Err(NetworkError::String("decrypt github Bearer failed!".to_string()));
                    }
                    secret = secret_res.unwrap();
                }
                let query_user = format!(
                    "GET {} HTTP/1.1\r\n\
                    HOST: {}\r\n\
                    Authorization: token {}\r\n\
                    User-Agent: curl/7.79.1\r\n\
                    Accept: application/json\r\n\r\n",
                    env::GITHUB_USER_SUFFIX,
                    env::GITHUB_API_HOST,
                    secret
                );
                let github_id_hash: String;
                let github_username: String;
                let simple_tls_client_params = format!("simple_tls_client_params: {:?}", query_user);
                println!("{:?}", simple_tls_client_params);
                match simple_tls_client(env::GITHUB_API_HOST, &query_user, 443) {
                    Ok(r) => {
                        let simple_tls_client_rsp = format!("simple_tls_client_rsp: {:?}", r);
                        println!("{:?}", simple_tls_client_rsp);
                        let github_id: i64 = match r["id"].as_i64() {
                            Some(id) => id,
                            _ => {
                                return Err(NetworkError::String("user id not found when query github user by token".to_string()));
                            }
                        };
                        let mut github_id_hex = format!("{:02x}", github_id);
                        let mut github_id_hex_len = github_id_hex.len() / 2;
                        if github_id_hex.len() % 2 == 1 {
                            github_id_hex_len += 1;
                            // for length of github_id_hex is odd, pad a prefix of zero
                            github_id_hex = format!("0{}", github_id_hex);
                        }
                        let mut github_id_hex_bytes = vec![0u8; github_id_hex_len];
                        match hex::decode_to_slice(github_id_hex, &mut github_id_hex_bytes) {
                            Ok(_) => (),
                            Err(e) => {
                                return Err(NetworkError::String(format!("err when decode_to_slice: {:?}", e)));
                            }
                        }
                        let mut hash = [0u8; 64];
                        match hex::encode_to_slice(&Code::Keccak256.digest(&github_id_hex_bytes).digest(), &mut hash) {
                            Ok(_) => (),
                            Err(e) => {
                                return Err(NetworkError::String(format!("err when encode_to_slice: {:?}", e)));
                            }
                        }
                        github_id_hash = match str::from_utf8(&hash) {
                            Ok(r) => format!("0x{}", r),
                            Err(e) => {
                                return Err(NetworkError::String(format!("err when from_utf8 for github_id_hash: {:?}", e)));
                            }
                        };
                        github_username = match r["login"].as_str() {
                            Some(name) => name.to_string(),
                            _ => {
                                return Err(NetworkError::String("login name not found when query github user by token".to_string()));
                            }
                        }
                    },
                    Err(e) => {
                        return Err(NetworkError::String(format!("error from simple_tls_client when query github user by token: {:?}", e)));
                    }
                }
                let enable_fields: &Value = &query_param["enableFields"];
                let mask_value: i64 = -1;
                let query = format!(
                    "{{ \"query\": \"query {{ user(login: \\\"{}\\\") {{ name login contributionsCollection \
                     {{ totalCommitContributions restrictedContributionsCount }} repositoriesContributedTo( \
                     first: 1 contributionTypes: [COMMIT, ISSUE, PULL_REQUEST, REPOSITORY]) {{ totalCount }} \
                     pullRequests(first: 1) {{ totalCount }} openIssues: issues(states: OPEN) {{ totalCount }} \
                     closedIssues: issues(states: CLOSED) {{ totalCount }} followers {{ totalCount }} repositories\
                     ( first: 100 ownerAffiliations: OWNER orderBy: {{direction: DESC, field: STARGAZERS}}) {{ \
                     totalCount nodes {{ stargazers {{ totalCount }} }} }} }} }}\" }}",
                    github_username
                );

                // let gihub_query_params = format!("gihub_query_params: {:?}", query);
                // println!("{:?}", gihub_query_params);

                let req = format!(
                    "POST {} HTTP/1.1\r\n\
                    HOST: {}\r\n\
                    Authorization: bearer {}\r\n\
                    User-Agent: curl/7.79.1\r\n\
                    Accept: */*\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: {}\r\n\r\n\
                    {}",
                    env::GITHUB_GRAPHQL_SUFFIX,
                    env::GITHUB_API_HOST,
                    secret,
                    query.len(),
                    query
                );
                let plaintext = match tls_post(env::GITHUB_API_HOST, &req, 443) {
                    Ok(r) => r,
                    Err(e) => {
                        let err = format!("tls_post to str: {:?}", e);
                        println!("{:?}", err);
                        return Err(NetworkError::String(err));
                    }
                };
                match parse_result(env::GITHUB_API_HOST, &plaintext) {
                    Ok(resp_json) => {
                        match panic::catch_unwind(|| {
                            if let Some(errors) = resp_json.pointer("/errors") {
                                panic!("errors from github api: {}", errors.to_string());
                            }
                            let zero_value = json!(0i64);
                            let followers: i64 = resp_json.pointer(
                                "/data/user/followers/totalCount"
                            ).unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            let empty_list_value = json!([]);
                            let repos: &Value = resp_json.pointer(
                                "/data/user/repositories/nodes"
                            ).unwrap_or(&empty_list_value);
                            let mut total_stars: i64 = 0;
                            for repo in repos.as_array().unwrap_or(&empty_list_value.as_array().unwrap()) {
                                total_stars += repo.pointer("/stargazers/totalCount").unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            }
                            let total_commits: i64 = resp_json.pointer(
                                "/data/user/contributionsCollection/totalCommitContributions"
                            ).unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            let total_prs: i64 = resp_json.pointer(
                                "/data/user/pullRequests/totalCount"
                            ).unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            let contributed_to: i64 = resp_json.pointer(
                                "/data/user/repositoriesContributedTo/totalCount"
                            ).unwrap_or(&zero_value).as_i64().unwrap_or(0);
                            let total_open_issues: &Value = resp_json.pointer("/data/user/openIssues/totalCount").unwrap_or(&zero_value);
                            let total_closed_issues: &Value = resp_json.pointer("/data/user/closedIssues/totalCount").unwrap_or(&zero_value);
                            let total_issues: i64 = total_open_issues.as_i64().unwrap_or(0) + total_closed_issues.as_i64().unwrap_or(0);
                            let req = format!(
                                "GET /signClaim?indexData0=e8578d748badbec07df94a3b4302f006&indexData1=\
                                8570338064081880388551501287622317849149962936429950615614006407425044481346&\
                                indexData2={}&indexData3={}&valueData0={}&valueData1={}&valueData2={}&valueData3={}&rsaPubkey={} HTTP/1.1\r\n\
                                HOST: {}\r\n\
                                User-Agent: curl/7.79.1\r\n\
                                Accept: */*\r\n\r\n",
                                if enable_fields["followers"].as_bool().unwrap_or(false) { followers } else { mask_value },
                                if enable_fields["totalStars"].as_bool().unwrap_or(false) { total_stars } else { mask_value },
                                if enable_fields["totalCommits"].as_bool().unwrap_or(false) { total_commits } else { mask_value },
                                if enable_fields["totalPrs"].as_bool().unwrap_or(false) { total_prs } else { mask_value },
                                if enable_fields["contributedTo"].as_bool().unwrap_or(false) { contributed_to } else { mask_value },
                                if enable_fields["totalIssues"].as_bool().unwrap_or(false) { total_issues } else { mask_value },
                                query_param["rsaPubKey"].as_str().unwrap_or(""),
                                env::SIGN_CLAIM_SGX_HOST
                            );

                            // let gihub_query_zk_req = format!("gihub_query_zk_req: {:?}", req);
                            // println!("{:?}", gihub_query_zk_req);


                            let zk_range_proof = simple_tls_client_no_cert_check(env::SIGN_CLAIM_SGX_HOST, &req, 12341).unwrap_or(json!({"result": {}}));
                            // let gihub_query_zk_resp = format!("gihub_query_zk_resp: {:?}", zk_range_proof);
                            // println!("{:?}", gihub_query_zk_resp);

                            let zk: &Value = &zk_range_proof;

                            json!({
                                "userIdHash": github_id_hash,
                                "zk_claim": {
                                    "encryptedClaim": zk["encryptedClaim"].as_str().unwrap_or(""),
                                    "signature": zk["signature"].as_str().unwrap_or(""),
                                    "signatureHash": zk["signatureHash"].as_str().unwrap_or("")
                                }
                            })
                        }) {
                            Ok(r) => Ok(r),
                            Err(e) => {
                                let err = format!("github user stats failed: {:?}", e);
                                println!("{:?}", err);
                                Err(NetworkError::String(err))
                            }
                        }
                    },
                    Err(e) => {
                        Err(e)
                    }
                }
            },
            _ => {
                Err(NetworkError::String(format!("Unexpected query_type: {:?}", query_type)))
            }
        }
    }
}

