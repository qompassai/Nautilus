use std::io;

use rocket_i18n::I18n;

use crate::dump::{self, Kind};
use crate::i18n_helpers::describe_query_error;
use crate::web::MyResponse;

use crate::database::{Database, KeyDatabase, Query};

#[get("/debug?<q>")]
pub fn debug_info(db: &rocket::State<KeyDatabase>, i18n: I18n, q: String) -> MyResponse {
    let query = match q.parse::<Query>() {
        Ok(query) => query,
        Err(_) => return MyResponse::bad_request_plain("bad request"),
    };
    let fp = match db.lookup_primary_fingerprint(&query) {
        Some(fp) => fp,
        None => return MyResponse::not_found_plain(describe_query_error(&i18n, &query)),
    };

    let armored_key = match db.by_fpr(&fp) {
        Some(armored_key) => armored_key,
        None => return MyResponse::not_found_plain(describe_query_error(&i18n, &query)),
    };

    let mut result = Vec::new();
    let dump_result = dump::dump(
        &mut io::Cursor::new(armored_key.as_bytes()),
        &mut result,
        false,
        false,
        None,
        32 * 4 + 80,
    );
    match dump_result {
        Ok(Kind::Cert) => match String::from_utf8(result) {
            Ok(dump_text) => MyResponse::plain(dump_text),
            Err(e) => MyResponse::ise(e.into()),
        },
        Ok(_) => MyResponse::ise(anyhow!("Internal parsing error!")),
        Err(e) => MyResponse::ise(e),
    }
}
