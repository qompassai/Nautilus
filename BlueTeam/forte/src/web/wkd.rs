use crate::database::{Database, KeyDatabase};
use crate::web::MyResponse;

// WKD queries
#[get("/.well-known/openpgpkey/<domain>/hu/<wkd_hash>")]
pub fn wkd_query(db: &rocket::State<KeyDatabase>, domain: String, wkd_hash: String) -> MyResponse {
    match db.by_domain_and_hash_wkd(&domain, &wkd_hash) {
        Some(key) => MyResponse::wkd(key, &wkd_hash),
        None => MyResponse::not_found_plain("No key found for this email address."),
    }
}

// Policy requests.
// 200 response with an empty body.
#[get("/.well-known/openpgpkey/<_domain>/policy")]
pub fn wkd_policy(_domain: String) -> MyResponse {
    MyResponse::plain("".to_string())
}
