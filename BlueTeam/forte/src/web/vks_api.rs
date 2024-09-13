use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use rocket::serde::json::Json;
use rocket_i18n::{I18n, Translations};
use serde_json::json;
use std::io::Cursor;

use crate::database::types::{Email, Fingerprint, KeyID};
use crate::database::{KeyDatabase, Query, StatefulTokens};
use crate::mail;
use crate::rate_limiter::RateLimiter;
use crate::tokens;

use crate::web;
use crate::web::vks;
use crate::web::vks::response::*;
use crate::web::{MyResponse, RequestOrigin};

use rocket::serde::json::Error as JsonError;

pub mod json {
    use crate::web::vks::response::EmailStatus;
    use std::collections::HashMap;

    #[derive(Deserialize)]
    pub struct VerifyRequest {
        pub token: String,
        pub addresses: Vec<String>,
        pub locale: Option<Vec<String>>,
    }

    #[derive(Deserialize)]
    pub struct UploadRequest {
        pub keytext: String,
    }

    #[derive(Serialize, Deserialize)]
    pub struct UploadResult {
        pub token: String,
        pub key_fpr: String,
        pub status: HashMap<String, EmailStatus>,
    }
}

type JsonResult = Result<serde_json::Value, JsonErrorResponse>;

#[derive(Debug)]
pub struct JsonErrorResponse(Status, String);

impl<'r> Responder<'r, 'static> for JsonErrorResponse {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let error_json = json!({"error": self.1});
        Response::build()
            .status(self.0)
            .sized_body(None, Cursor::new(error_json.to_string()))
            .header(ContentType::JSON)
            .ok()
    }
}

fn json_or_error<T>(data: Result<Json<T>, JsonError>) -> Result<Json<T>, JsonErrorResponse> {
    match data {
        Ok(data) => Ok(data),
        Err(JsonError::Io(_)) => Err(JsonErrorResponse(
            Status::InternalServerError,
            "i/o error!".to_owned(),
        )),
        Err(JsonError::Parse(_, e)) => Err(JsonErrorResponse(Status::BadRequest, e.to_string())),
    }
}

fn upload_ok_json(response: UploadResponse) -> Result<serde_json::Value, JsonErrorResponse> {
    match response {
        UploadResponse::Ok {
            token,
            key_fpr,
            status,
            ..
        } => Ok(json!(json::UploadResult {
            token,
            key_fpr,
            status
        })),
        UploadResponse::OkMulti { key_fprs } => Ok(json!(key_fprs)),
        UploadResponse::Error(error) => Err(JsonErrorResponse(Status::BadRequest, error)),
    }
}

#[post("/vks/v1/upload", format = "json", data = "<data>")]
pub fn upload_json(
    db: &rocket::State<KeyDatabase>,
    tokens_stateless: &rocket::State<tokens::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    data: Result<Json<json::UploadRequest>, JsonError>,
) -> JsonResult {
    let data = json_or_error(data)?;
    use std::io::Cursor;
    let data_reader = Cursor::new(data.keytext.as_bytes());
    let result = vks::process_key(db, &i18n, tokens_stateless, rate_limiter, data_reader);
    upload_ok_json(result)
}

#[post("/vks/v1/upload", rank = 2)]
pub fn upload_fallback(origin: RequestOrigin) -> JsonErrorResponse {
    let error_msg = format!(
        "expected application/json data. see {}/about/api for api docs.",
        origin.get_base_uri()
    );
    JsonErrorResponse(Status::BadRequest, error_msg)
}

fn get_locale(langs: &rocket::State<Translations>, locales: Vec<String>) -> I18n {
    locales
        .iter()
        .flat_map(|lang| lang.split(|c| c == '-' || c == ';' || c == '_').next())
        .flat_map(|lang| langs.iter().find(|(trans, _)| trans == &lang))
        .next()
        .or_else(|| langs.iter().find(|(trans, _)| trans == &"en"))
        .map(|(lang, catalog)| I18n {
            catalog: catalog.clone(),
            lang,
        })
        .expect("Expected to have an english translation!")
}

#[post("/vks/v1/request-verify", format = "json", data = "<data>")]
pub fn request_verify_json(
    db: &rocket::State<KeyDatabase>,
    langs: &rocket::State<Translations>,
    origin: RequestOrigin,
    token_stateful: &rocket::State<StatefulTokens>,
    token_stateless: &rocket::State<tokens::Service>,
    mail_service: &rocket::State<mail::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    data: Result<Json<json::VerifyRequest>, JsonError>,
) -> JsonResult {
    let data = json_or_error(data)?;
    let json::VerifyRequest {
        token,
        addresses,
        locale,
    } = data.into_inner();
    let i18n = get_locale(langs, locale.unwrap_or_default());
    let result = vks::request_verify(
        db,
        &origin,
        token_stateful,
        token_stateless,
        mail_service,
        rate_limiter,
        &i18n,
        token,
        addresses,
    );
    upload_ok_json(result)
}

#[post("/vks/v1/request-verify", rank = 2)]
pub fn request_verify_fallback(origin: RequestOrigin) -> JsonErrorResponse {
    let error_msg = format!(
        "expected application/json data. see {}/about/api for api docs.",
        origin.get_base_uri()
    );
    JsonErrorResponse(Status::BadRequest, error_msg)
}

#[get("/vks/v1/by-fingerprint/<fpr>")]
pub fn vks_v1_by_fingerprint(
    db: &rocket::State<KeyDatabase>,
    i18n: I18n,
    fpr: String,
) -> MyResponse {
    let query = match fpr.parse::<Fingerprint>() {
        Ok(fpr) => Query::ByFingerprint(fpr),
        Err(_) => return MyResponse::bad_request_plain("malformed fingerprint"),
    };

    web::key_to_response_plain(db, i18n, query)
}

#[get("/vks/v1/by-email/<email>")]
pub fn vks_v1_by_email(db: &rocket::State<KeyDatabase>, i18n: I18n, email: String) -> MyResponse {
    let email = email.replace("%40", "@");
    let query = match email.parse::<Email>() {
        Ok(email) => Query::ByEmail(email),
        Err(_) => return MyResponse::bad_request_plain("malformed e-mail address"),
    };

    web::key_to_response_plain(db, i18n, query)
}

#[get("/vks/v1/by-keyid/<kid>")]
pub fn vks_v1_by_keyid(db: &rocket::State<KeyDatabase>, i18n: I18n, kid: String) -> MyResponse {
    let query = match kid.parse::<KeyID>() {
        Ok(keyid) => Query::ByKeyID(keyid),
        Err(_) => return MyResponse::bad_request_plain("malformed key id"),
    };

    web::key_to_response_plain(db, i18n, query)
}
