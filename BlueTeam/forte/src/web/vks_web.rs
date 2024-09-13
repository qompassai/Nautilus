use crate::Result;

use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;
use multipart::server::Multipart;

use gettext_macros::i18n;
use rocket::data::ByteUnit;
use rocket::form::Form;
use rocket::form::ValueField;
use rocket::http::ContentType;
use rocket::Data;
use rocket_i18n::I18n;
use url::percent_encoding::percent_decode;

use crate::database::{Database, KeyDatabase, Query, StatefulTokens};
use crate::i18n_helpers::describe_query_error;
use crate::mail;
use crate::rate_limiter::RateLimiter;
use crate::tokens;
use crate::web::{MyResponse, RequestOrigin};

use std::collections::HashMap;
use std::io::Cursor;

use crate::web::vks;
use crate::web::vks::response::*;

const UPLOAD_LIMIT: ByteUnit = ByteUnit::Mebibyte(1);

mod forms {
    #[derive(FromForm, Deserialize)]
    pub struct VerifyRequest {
        pub token: String,
        pub address: String,
    }

    #[derive(Deserialize)]
    pub struct UploadRequest {
        pub keytext: String,
    }
}

mod template {
    #[derive(Serialize)]
    pub struct VerifyForm {
        pub token: String,
    }

    #[derive(Serialize)]
    pub struct Verify {
        pub key_fpr: String,
        pub userid: String,
        pub userid_link: String,
    }

    #[derive(Serialize)]
    pub struct Search {
        pub query: String,
        pub fpr: String,
    }

    #[derive(Serialize)]
    pub struct VerificationSent {
        pub key_fpr: String,
        pub key_link: String,
        pub is_revoked: bool,
        pub token: String,
        pub email_published: Vec<String>,
        pub email_unpublished: Vec<UploadUidStatus>,
        pub count_revoked_one: bool,
        pub count_revoked: usize,
        pub count_unparsed_one: bool,
        pub count_unparsed: usize,
    }

    #[derive(Serialize)]
    pub struct UploadOkKey {
        pub key_fpr: String,
        pub key_link: String,
    }

    #[derive(Serialize)]
    pub struct UploadOkMultiple {
        pub keys: Vec<UploadOkKey>,
    }

    #[derive(Serialize)]
    pub struct UploadUidStatus {
        pub address: String,
        pub requested: bool,
    }
}

impl MyResponse {
    fn upload_response_quick(response: UploadResponse, i18n: I18n, origin: RequestOrigin) -> Self {
        match response {
            UploadResponse::Ok { token, .. } => {
                let uri = uri!(quick_upload_proceed(token));
                let text = format!(
                    "Key successfully uploaded. Proceed with verification here:\n{}{}\n",
                    origin.get_base_uri(),
                    uri
                );
                MyResponse::plain(text)
            }
            UploadResponse::OkMulti { key_fprs } => MyResponse::plain(format!(
                "Uploaded {} keys. For verification, please upload keys individually.\n",
                key_fprs.len()
            )),
            UploadResponse::Error(error) => {
                MyResponse::bad_request("400-plain", anyhow!(error), i18n, origin)
            }
        }
    }

    fn upload_response(response: UploadResponse, i18n: I18n, origin: RequestOrigin) -> Self {
        match response {
            UploadResponse::Ok {
                token,
                key_fpr,
                is_revoked,
                count_unparsed,
                status,
                ..
            } => Self::upload_ok(
                token,
                key_fpr,
                is_revoked,
                count_unparsed,
                status,
                i18n,
                origin,
            ),
            UploadResponse::OkMulti { key_fprs } => Self::upload_ok_multi(key_fprs, i18n, origin),
            UploadResponse::Error(error) => {
                MyResponse::bad_request("upload/upload", anyhow!(error), i18n, origin)
            }
        }
    }

    fn upload_ok(
        token: String,
        key_fpr: String,
        is_revoked: bool,
        count_unparsed: usize,
        uid_status: HashMap<String, EmailStatus>,
        i18n: I18n,
        origin: RequestOrigin,
    ) -> Self {
        let key_link = uri!(search(q = &key_fpr)).to_string();

        let count_revoked = uid_status
            .iter()
            .filter(|(_, status)| **status == EmailStatus::Revoked)
            .count();

        let mut email_published: Vec<_> = uid_status
            .iter()
            .filter(|(_, status)| **status == EmailStatus::Published)
            .map(|(email, _)| email.to_string())
            .collect();
        email_published.sort_unstable();

        let mut email_unpublished: Vec<_> = uid_status
            .into_iter()
            .filter(|(_, status)| {
                *status == EmailStatus::Unpublished || *status == EmailStatus::Pending
            })
            .map(|(email, status)| template::UploadUidStatus {
                address: email,
                requested: status == EmailStatus::Pending,
            })
            .collect();
        email_unpublished.sort_unstable_by(|fst, snd| fst.address.cmp(&snd.address));

        let context = template::VerificationSent {
            is_revoked,
            key_fpr,
            key_link,
            token,
            email_published,
            email_unpublished,
            count_revoked_one: count_revoked == 1,
            count_revoked,
            count_unparsed_one: count_unparsed == 1,
            count_unparsed,
        };
        MyResponse::ok("upload/upload-ok", context, i18n, origin)
    }

    fn upload_ok_multi(key_fprs: Vec<String>, i18n: I18n, origin: RequestOrigin) -> Self {
        let keys = key_fprs
            .into_iter()
            .map(|fpr| {
                let key_link = uri!(search(q = &fpr)).to_string();
                template::UploadOkKey {
                    key_fpr: fpr,
                    key_link,
                }
            })
            .collect();

        let context = template::UploadOkMultiple { keys };

        MyResponse::ok("upload/upload-ok-multiple", context, i18n, origin)
    }
}

#[get("/upload")]
pub fn upload(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("upload/upload", i18n, origin)
}

#[post("/upload/submit", format = "multipart/form-data", data = "<data>")]
pub async fn upload_post_form_data(
    db: &rocket::State<KeyDatabase>,
    origin: RequestOrigin,
    tokens_stateless: &rocket::State<tokens::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    cont_type: &ContentType,
    data: Data<'_>,
) -> MyResponse {
    match process_upload(db, tokens_stateless, rate_limiter, &i18n, data, cont_type).await {
        Ok(response) => MyResponse::upload_response(response, i18n, origin),
        Err(err) => MyResponse::bad_request("upload/upload", err, i18n, origin),
    }
}

pub async fn process_post_form_data(
    db: &rocket::State<KeyDatabase>,
    tokens_stateless: &rocket::State<tokens::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    cont_type: &ContentType,
    data: Data<'_>,
) -> Result<UploadResponse> {
    process_upload(db, tokens_stateless, rate_limiter, &i18n, data, cont_type).await
}

#[get("/search?<q>")]
pub fn search(
    db: &rocket::State<KeyDatabase>,
    origin: RequestOrigin,
    i18n: I18n,
    q: String,
) -> MyResponse {
    match q.parse::<Query>() {
        Ok(query) => key_to_response(db, origin, i18n, q, query),
        Err(e) => MyResponse::bad_request("index", e, i18n, origin),
    }
}

fn key_to_response(
    db: &rocket::State<KeyDatabase>,
    origin: RequestOrigin,
    i18n: I18n,
    query_string: String,
    query: Query,
) -> MyResponse {
    let fp = if let Some(fp) = db.lookup_primary_fingerprint(&query) {
        fp
    } else if query.is_invalid() {
        return MyResponse::bad_request(
            "index",
            anyhow!(describe_query_error(&i18n, &query)),
            i18n,
            origin,
        );
    } else {
        return MyResponse::not_found(None, describe_query_error(&i18n, &query), i18n, origin);
    };

    let context = template::Search {
        query: query_string,
        fpr: fp.to_string(),
    };

    MyResponse::ok("found", context, i18n, origin)
}

#[put("/", data = "<data>")]
pub async fn quick_upload(
    db: &rocket::State<KeyDatabase>,
    tokens_stateless: &rocket::State<tokens::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    origin: RequestOrigin,
    data: Data<'_>,
) -> MyResponse {
    let buf = match data.open(UPLOAD_LIMIT).into_bytes().await {
        Ok(buf) => buf.into_inner(),
        Err(error) => return MyResponse::bad_request("400-plain", anyhow!(error), i18n, origin),
    };

    MyResponse::upload_response_quick(
        vks::process_key(db, &i18n, tokens_stateless, rate_limiter, Cursor::new(buf)),
        i18n,
        origin,
    )
}

#[get("/upload/<token>", rank = 2)]
pub fn quick_upload_proceed(
    db: &rocket::State<KeyDatabase>,
    origin: RequestOrigin,
    token_stateful: &rocket::State<StatefulTokens>,
    token_stateless: &rocket::State<tokens::Service>,
    mail_service: &rocket::State<mail::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    token: String,
) -> MyResponse {
    let result = vks::request_verify(
        db,
        &origin,
        token_stateful,
        token_stateless,
        mail_service,
        rate_limiter,
        &i18n,
        token,
        vec![],
    );
    MyResponse::upload_response(result, i18n, origin)
}

#[post(
    "/upload/submit",
    format = "application/x-www-form-urlencoded",
    data = "<data>"
)]
pub async fn upload_post_form(
    db: &rocket::State<KeyDatabase>,
    origin: RequestOrigin,
    tokens_stateless: &rocket::State<tokens::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    data: Data<'_>,
) -> MyResponse {
    match process_post_form(db, tokens_stateless, rate_limiter, &i18n, data).await {
        Ok(response) => MyResponse::upload_response(response, i18n, origin),
        Err(err) => MyResponse::bad_request("upload/upload", err, i18n, origin),
    }
}

pub async fn process_post_form(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    i18n: &I18n,
    data: Data<'_>,
) -> Result<UploadResponse> {
    // application/x-www-form-urlencoded
    let buf = data.open(UPLOAD_LIMIT).into_bytes().await?;

    for ValueField { name, value } in Form::values(&*String::from_utf8_lossy(&buf)) {
        let decoded_value = percent_decode(value.as_bytes())
            .decode_utf8()
            .map_err(|_| anyhow!("`Content-Type: application/x-www-form-urlencoded` not valid"))?;

        if name.to_string().as_str() == "keytext" {
            return Ok(vks::process_key(
                db,
                i18n,
                tokens_stateless,
                rate_limiter,
                Cursor::new(decoded_value.as_bytes()),
            ));
        }
    }

    Err(anyhow!("No keytext found"))
}

async fn process_upload(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    i18n: &I18n,
    data: Data<'_>,
    cont_type: &ContentType,
) -> Result<UploadResponse> {
    // multipart/form-data
    let (_, boundary) = cont_type
        .params()
        .find(|&(k, _)| k == "boundary")
        .ok_or_else(|| {
            anyhow!(
                "`Content-Type: multipart/form-data` \
                                      boundary param not provided"
            )
        })?;

    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    let data = Cursor::new(data.open(UPLOAD_LIMIT).into_bytes().await?.value);
    match Multipart::with_body(data, boundary).save().temp() {
        Full(entries) => process_multipart(db, tokens_stateless, rate_limiter, i18n, entries),
        Partial(partial, _) => {
            process_multipart(db, tokens_stateless, rate_limiter, i18n, partial.entries)
        }
        Error(err) => Err(err.into()),
    }
}

fn process_multipart(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    i18n: &I18n,
    entries: Entries,
) -> Result<UploadResponse> {
    match entries.fields.get("keytext") {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable()?;
            Ok(vks::process_key(
                db,
                i18n,
                tokens_stateless,
                rate_limiter,
                reader,
            ))
        }
        Some(_) => Err(anyhow!("Multiple keytexts found")),
        None => Err(anyhow!("No keytext found")),
    }
}

#[post(
    "/upload/request-verify",
    format = "application/x-www-form-urlencoded",
    data = "<request>"
)]
pub fn request_verify_form(
    db: &rocket::State<KeyDatabase>,
    origin: RequestOrigin,
    token_stateful: &rocket::State<StatefulTokens>,
    token_stateless: &rocket::State<tokens::Service>,
    mail_service: &rocket::State<mail::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    request: Form<forms::VerifyRequest>,
) -> MyResponse {
    let forms::VerifyRequest { token, address } = request.into_inner();
    let result = vks::request_verify(
        db,
        &origin,
        token_stateful,
        token_stateless,
        mail_service,
        rate_limiter,
        &i18n,
        token,
        vec![address],
    );
    MyResponse::upload_response(result, i18n, origin)
}

#[post(
    "/upload/request-verify",
    format = "multipart/form-data",
    data = "<request>"
)]
pub fn request_verify_form_data(
    db: &rocket::State<KeyDatabase>,
    origin: RequestOrigin,
    token_stateful: &rocket::State<StatefulTokens>,
    token_stateless: &rocket::State<tokens::Service>,
    mail_service: &rocket::State<mail::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    request: Form<forms::VerifyRequest>,
) -> MyResponse {
    let forms::VerifyRequest { token, address } = request.into_inner();
    let result = vks::request_verify(
        db,
        &origin,
        token_stateful,
        token_stateless,
        mail_service,
        rate_limiter,
        &i18n,
        token,
        vec![address],
    );
    MyResponse::upload_response(result, i18n, origin)
}

#[post("/verify/<token>")]
pub fn verify_confirm(
    db: &rocket::State<KeyDatabase>,
    origin: RequestOrigin,
    token_service: &rocket::State<StatefulTokens>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    token: String,
) -> MyResponse {
    let rate_limit_id = format!("verify-token-{}", &token);
    match vks::verify_confirm(db, &i18n, token_service, token) {
        PublishResponse::Ok { fingerprint, email } => {
            rate_limiter.action_perform(rate_limit_id);
            let userid_link = uri!(search(q = &email)).to_string();
            let context = template::Verify {
                userid: email,
                key_fpr: fingerprint,
                userid_link,
            };

            MyResponse::ok("upload/publish-result", context, i18n, origin)
        }
        PublishResponse::Error(error) => {
            let error_msg = if rate_limiter.action_check(rate_limit_id) {
                anyhow!(error)
            } else {
                anyhow!(i18n!(
                    i18n.catalog,
                    "This address has already been verified."
                ))
            };
            MyResponse::bad_request("400", error_msg, i18n, origin)
        }
    }
}

#[get("/verify/<token>")]
pub fn verify_confirm_form(origin: RequestOrigin, i18n: I18n, token: String) -> MyResponse {
    MyResponse::ok(
        "upload/verification-form",
        template::VerifyForm { token },
        i18n,
        origin,
    )
}
