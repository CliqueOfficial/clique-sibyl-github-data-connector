use std::prelude::v1::*;
use sibyl_base_data_connector::base::DataConnector;
use sibyl_base_data_connector::serde_json::json;
use std::string::ToString;
use std::iter::IntoIterator;
use sibyl_base_data_connector::serde_json::Value;
use std::str;
use String;
use std::panic;
// use std::untrusted::time::SystemTimeEx;
use sibyl_base_data_connector::utils::{parse_result, tls_post};
use sibyl_base_data_connector::utils::simple_tls_client;
use multihash::{Code, MultihashDigest};

// Github GraphQL API
const GITHUB_API_HOST: &'static str = "api.github.com";
const GITHUB_GRAPHQL_SUFFIX: &'static str = "/graphql";
const GITHUB_USER_SUFFIX: &'static str = "/user";
const SIGN_CLAIM_SGX_HOST: &'static str = "clique-signclaim";

pub struct GithubConnector {

}

impl DataConnector for GithubConnector {
    fn query(&self, query_type: &Value, query_param: &Value) -> Result<Value, String> {
        let query_type_str = match query_type.as_str() {
            Some(r) => r,
            _ => {
                let err = format!("query_type to str failed");
                println!("{:?}", err);
                return Err(err);
            }
        };
        match query_type_str {
            "github_user_stats_zk_claim" => {
                let queryUser = format!(
                    "GET {} HTTP/1.1\r\n\
                    HOST: {}\r\n\
                    Authorization: token {}\r\n\
                    User-Agent: curl/7.79.1\r\n\
                    Accept: PostmanRuntime/7.31.3\r\n\r\n",
                    GITHUB_USER_SUFFIX,
                    GITHUB_API_HOST,
                    query_param["bearer"].as_str().unwrap_or("")
                );
                let mut githubIdHash: String;
                let mut githubUsername: String;
                match simple_tls_client(GITHUB_API_HOST, &queryUser, 443) {
                    Ok(r) => {
                        let github_id: i64 = match r["result"]["id"].as_i64() {
                            Some(id) => id,
                            _ => {
                                return Err("user id not found when query github user by token".to_string());
                            }
                        };
                        let mut github_id_hex = format!("{:02x}", github_id);
                        if github_id_hex.len() % 2 == 1 {
                            github_id_hex = format!("0x0{}", github_id_hex);
                        } else {
                            github_id_hex = format!("0x{}", github_id_hex);
                        }
                        let mut hash = [0u8; 64];
                        match hex::encode_to_slice(&Code::Keccak256.digest(github_id_hex.as_bytes()).digest(), &mut hash) {
                            Ok(_) => (),
                            Err(e) => {
                                return Err("err when encode_to_slice".to_string());
                            }
                        };
                        let mut github_id_hex = format!("{:02x}", github_id);
                        githubIdHash = match str::from_utf8(&hash) {
                            Ok(r) => r.to_string(),
                            Err(e) => {
                                return Err("err when from_utf7 for github_id_hash".to_string());
                            }
                        };
                        githubIdHash = format!("0x{}", githubIdHash);
                        githubUsername = match r["result"]["login"].as_str() {
                            Some(name) => name.to_string(),
                            _ => {
                                return Err("login name not found when query github user by token".to_string());
                            }
                        }
                    },
                    Err(e) => {
                        return Err(format!("error from simple_tls_client when query github user by token: {:?}", e));
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
                    githubUsername
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
                    GITHUB_GRAPHQL_SUFFIX,
                    GITHUB_API_HOST,
                    query_param["bearer"].as_str().unwrap_or(""),
                    query.len(),
                    query
                );
                let plaintext = match tls_post(GITHUB_API_HOST, &req, 443) {
                    Ok(r) => r,
                    Err(e) => {
                        let err = format!("tls_post to str: {:?}", e);
                        println!("{:?}", err);
                        return Err(err);
                    }
                };
                let mut reason = "".to_string();
                let mut result: Value = json!("fail");
                match parse_result(&plaintext) {
                    Ok(resp_json) => {
                        result = match panic::catch_unwind(|| {
                            let zero_value = json!(0i64);
                            let empty_str_value = json!("");
                            let user_name: &Value = resp_json.pointer(
                                "/data/user/name"
                            ).unwrap_or(resp_json.pointer(
                                "/data/user/login"
                            ).unwrap_or(&empty_str_value));
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
                                if enable_fields["total_stars"].as_bool().unwrap_or(false) { total_stars } else { mask_value },
                                if enable_fields["total_commits"].as_bool().unwrap_or(false) { total_commits } else { mask_value },
                                if enable_fields["total_prs"].as_bool().unwrap_or(false) { total_prs } else { mask_value },
                                if enable_fields["contributed_to"].as_bool().unwrap_or(false) { contributed_to } else { mask_value },
                                if enable_fields["total_issues"].as_bool().unwrap_or(false) { total_issues } else { mask_value },
                                query_param["rsaPubkey"].as_str().unwrap_or(""),
                                SIGN_CLAIM_SGX_HOST
                            );
                            let zk_range_proof = simple_tls_client(SIGN_CLAIM_SGX_HOST, &req, 12341).unwrap_or(json!({"result": {}}));
                            let zk: &Value = &zk_range_proof["result"];
                            return json!({
                                "userIdHash": githubIdHash,
                                "zk_claim": {
                                    "encryptedClaim": zk["encryptedClaim"].as_str().unwrap_or(""),
                                    "signature": zk["signature"].as_str().unwrap_or(""),
                                    "signatureHash": zk["signatureHash"].as_str().unwrap_or("")
                                }
                            });
                        }) {
                            Ok(r) => r,
                            Err(e) => {
                                let err = format!("github user stats failed: {:?}", e);
                                println!("{:?}", err);
                                return Err(err);
                            }
                        };
                    },
                    Err(e) => {
                        reason = e;
                    }
                }
                // println!("parse result {:?}", result);
                Ok(json!({
                    "result": result,
                    "reason": reason
                }))
            },
            _ => {
                Err(format!("Unexpected query_type: {:?}", query_type))
            }
        }
    }
}

