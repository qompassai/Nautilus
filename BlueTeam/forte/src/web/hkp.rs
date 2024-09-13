use std::fmt;

use std::collections::HashMap;
use std::str::FromStr;
use std::time::SystemTime;

use rocket::http::ContentType;
use rocket::Data;
use rocket_i18n::I18n;
use url::percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};

use crate::database::types::{Email, Fingerprint, KeyID};
use crate::database::{Database, KeyDatabase, Query};

use crate::i18n_helpers::describe_query_error;
use crate::rate_limiter::RateLimiter;

use crate::tokens;

use crate::mail;
use crate::web;
use crate::web::vks::response::EmailStatus;
use crate::web::vks::response::UploadResponse;
use crate::web::{vks_web, MyResponse, RequestOrigin};

#[derive(Debug)]
pub enum Hkp {
    Fingerprint { fpr: Fingerprint },
    KeyID { keyid: KeyID },
    ShortKeyID { query: String },
    Email { email: Email },
}

impl fmt::Display for Hkp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Hkp::Fingerprint { ref fpr, .. } => write!(f, "{}", fpr),
            Hkp::KeyID { ref keyid, .. } => write!(f, "{}", keyid),
            Hkp::Email { ref email, .. } => write!(f, "{}", email),
            Hkp::ShortKeyID { ref query, .. } => write!(f, "{}", query),
        }
    }
}

impl std::str::FromStr for Hkp {
    type Err = anyhow::Error;
    fn from_str(search: &str) -> Result<Self, Self::Err> {
        let maybe_fpr = Fingerprint::from_str(search);
        let maybe_keyid = KeyID::from_str(search);

        let looks_like_short_key_id = !search.contains('@')
            && (search.starts_with("0x") && search.len() < 16 || search.len() == 8);
        let hkp = if looks_like_short_key_id {
            Hkp::ShortKeyID {
                query: search.to_string(),
            }
        } else if let Ok(fpr) = maybe_fpr {
            Hkp::Fingerprint { fpr }
        } else if let Ok(keyid) = maybe_keyid {
            Hkp::KeyID { keyid }
        } else {
            match Email::from_str(search) {
                Ok(email) => Hkp::Email { email },
                Err(_) => return Err(anyhow::anyhow!("Invalid search query!")),
            }
        };
        Ok(hkp)
    }
}

#[post("/pks/add", format = "multipart/form-data", data = "<data>")]
pub async fn pks_add_form_data(
    db: &rocket::State<KeyDatabase>,
    tokens_stateless: &rocket::State<tokens::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    cont_type: &ContentType,
    data: Data<'_>,
) -> MyResponse {
    match vks_web::process_post_form_data(db, tokens_stateless, rate_limiter, i18n, cont_type, data)
        .await
    {
        Ok(_) => MyResponse::plain("Ok".into()),
        Err(err) => MyResponse::ise(err),
    }
}

#[post(
    "/pks/add",
    format = "application/x-www-form-urlencoded",
    data = "<data>"
)]
pub async fn pks_add_form(
    origin: RequestOrigin,
    db: &rocket::State<KeyDatabase>,
    tokens_stateless: &rocket::State<tokens::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    mail_service: &rocket::State<mail::Service>,
    i18n: I18n,
    data: Data<'_>,
) -> MyResponse {
    match vks_web::process_post_form(db, tokens_stateless, rate_limiter, &i18n, data).await {
        Ok(UploadResponse::Ok {
            is_new_key,
            key_fpr,
            primary_uid,
            token,
            status,
            ..
        }) => {
            let msg = pks_add_ok(
                &origin,
                mail_service,
                rate_limiter,
                token,
                status,
                is_new_key,
                key_fpr,
                primary_uid,
            );
            MyResponse::plain(msg)
        }
        Ok(_) => {
            let msg = format!("Upload successful. Please note that identity information will only be published after verification. See {baseuri}/about/usage#gnupg-upload", baseuri = origin.get_base_uri());
            MyResponse::plain(msg)
        }
        Err(err) => MyResponse::ise(err),
    }
}

fn pks_add_ok(
    origin: &RequestOrigin,
    mail_service: &mail::Service,
    rate_limiter: &RateLimiter,
    token: String,
    status: HashMap<String, EmailStatus>,
    is_new_key: bool,
    key_fpr: String,
    primary_uid: Option<Email>,
) -> String {
    if primary_uid.is_none() {
        return format!("Upload successful. Please note that identity information will only be published after verification. See {baseuri}/about/usage#gnupg-upload", baseuri = origin.get_base_uri());
    }
    let primary_uid = primary_uid.unwrap();

    if is_new_key {
        if send_welcome_mail(origin, mail_service, key_fpr, &primary_uid, token) {
            rate_limiter.action_perform(format!("hkp-sent-{}", &primary_uid));
            return "Upload successful. This is a new key, a welcome email has been sent."
                .to_string();
        }
        return format!("Upload successful. Please note that identity information will only be published after verification. See {baseuri}/about/usage#gnupg-upload", baseuri = origin.get_base_uri());
    }

    let has_unverified = status.iter().any(|(_, v)| *v == EmailStatus::Unpublished);
    if !has_unverified {
        return "Upload successful.".to_string();
    }

    return format!("Upload successful. Please note that identity information will only be published after verification. See {baseuri}/about/usage#gnupg-upload", baseuri = origin.get_base_uri());
}

fn send_welcome_mail(
    origin: &RequestOrigin,
    mail_service: &mail::Service,
    fpr: String,
    primary_uid: &Email,
    token: String,
) -> bool {
    mail_service
        .send_welcome(origin.get_base_uri(), fpr, primary_uid, &token)
        .is_ok()
}

#[get("/pks/lookup?<op>&<search>")]
pub fn pks_lookup(
    db: &rocket::State<KeyDatabase>,
    i18n: I18n,
    op: Option<String>,
    search: Option<String>,
) -> MyResponse {
    let search = search.unwrap_or_default();
    let key = match Hkp::from_str(&search) {
        Ok(key) => key,
        Err(_) => return MyResponse::bad_request_plain("Invalid search query!"),
    };
    let query = match key {
        Hkp::Fingerprint { fpr } => Query::ByFingerprint(fpr),
        Hkp::KeyID { keyid } => Query::ByKeyID(keyid),
        Hkp::Email { email } => Query::ByEmail(email),
        Hkp::ShortKeyID { query: _, .. } => {
            return MyResponse::bad_request_plain(
                "Search by short key ids is not supported, sorry!",
            );
        }
    };

    if let Some(op) = op {
        match op.as_str() {
            "index" => key_to_hkp_index(db, i18n, query),
            "get" => web::key_to_response_plain(db, i18n, query),
            "vindex" => MyResponse::not_implemented_plain("vindex not implemented"),
            s if s.starts_with("x-") => {
                MyResponse::not_implemented_plain("x-* operations not implemented")
            }
            &_ => MyResponse::bad_request_plain("Invalid op parameter!"),
        }
    } else {
        MyResponse::bad_request_plain("op parameter required!")
    }
}

#[get("/pks/internal/index/<query_string>")]
pub fn pks_internal_index(
    db: &rocket::State<KeyDatabase>,
    i18n: I18n,
    query_string: String,
) -> MyResponse {
    match query_string.parse() {
        Ok(query) => key_to_hkp_index(db, i18n, query),
        Err(_) => MyResponse::bad_request_plain("Invalid search query!"),
    }
}

fn key_to_hkp_index(db: &rocket::State<KeyDatabase>, i18n: I18n, query: Query) -> MyResponse {
    use sequoia_openpgp::policy::StandardPolicy;
    use sequoia_openpgp::types::RevocationStatus;

    let tpk = match db.lookup(&query) {
        Ok(Some(tpk)) => tpk,
        Ok(None) => return MyResponse::not_found_plain(describe_query_error(&i18n, &query)),
        Err(err) => {
            return MyResponse::ise(err);
        }
    };
    let mut out = String::default();
    let p = tpk.primary_key();

    let policy = &StandardPolicy::new();

    let ctime = format!(
        "{}",
        p.creation_time()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let is_rev = if tpk.revocation_status(policy, None) != RevocationStatus::NotAsFarAsWeKnow {
        "r"
    } else {
        ""
    };
    let algo: u8 = p.pk_algo().into();

    out.push_str("info:1:1\r\n");
    out.push_str(&format!(
        "pub:{}:{}:{}:{}:{}:{}{}\r\n",
        p.fingerprint().to_string().replace(" ", ""),
        algo,
        p.mpis().bits().unwrap_or(0),
        ctime,
        "",
        "",
        is_rev
    ));

    for uid in tpk.userids() {
        let uidstr = uid.userid().to_string();
        let u = utf8_percent_encode(&uidstr, DEFAULT_ENCODE_SET).to_string();
        let ctime = uid
            .binding_signature(policy, None)
            .ok()
            .and_then(|x| x.signature_creation_time())
            .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|x| format!("{}", x.as_secs()))
            .unwrap_or_default();
        let is_rev = if uid.revocation_status(policy, None) != RevocationStatus::NotAsFarAsWeKnow {
            "r"
        } else {
            ""
        };

        out.push_str(&format!("uid:{}:{}:{}:{}{}\r\n", u, ctime, "", "", is_rev));
    }

    MyResponse::plain(out)
}

#[cfg(test)]
mod tests {
    use rocket::http::ContentType;
    use rocket::http::Status;

    use sequoia_openpgp::serialize::Serialize;

    use crate::mail::pop_mail;
    use crate::web::tests::*;

    #[test]
    fn hkp() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // eprintln!("LEAKING: {:?}", tmpdir);
        // ::std::mem::forget(tmpdir);

        // Generate a key and upload it.
        let tpk = build_cert("foo@invalid.example.com");

        // Prepare to /pks/add
        let mut armored = Vec::new();
        {
            use sequoia_openpgp::armor::{Kind, Writer};
            let mut w = Writer::new(&mut armored, Kind::PublicKey).unwrap();
            tpk.serialize(&mut w).unwrap();
            w.finalize().unwrap();
        }
        let mut post_data = String::from("keytext=");
        for enc in url::form_urlencoded::byte_serialize(&armored) {
            post_data.push_str(enc);
        }

        // Add!
        let response = client
            .post("/pks/add")
            .body(post_data.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        eprintln!("response: {}", body);

        // Check that we get a welcome mail
        let welcome_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(welcome_mail.is_some());

        // Add!
        let response = client
            .post("/pks/add")
            .body(post_data.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        eprintln!("response: {}", body);

        // No second email right after the welcome one!
        let upload_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(upload_mail.is_none());

        // We should not be able to look it up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // And check that we can get it back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 0);

        // Upload the same key again, make sure the welcome mail is not sent again
        let response = client
            .post("/pks/add")
            .body(post_data.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let welcome_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(welcome_mail.is_none());

        assert_consistency(client.rocket());
    }

    #[test]
    fn hkp_add_two() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate two keys and upload them.
        let tpk_0 = build_cert("foo@invalid.example.com");
        let tpk_1 = build_cert("bar@invalid.example.com");

        // Prepare to /pks/add
        let mut armored_first = Vec::new();
        let mut armored_both = Vec::new();
        {
            use sequoia_openpgp::armor::{Kind, Writer};
            let mut w = Writer::new(&mut armored_both, Kind::PublicKey).unwrap();
            tpk_0.serialize(&mut w).unwrap();
            tpk_1.serialize(&mut w).unwrap();
            w.finalize().unwrap();
        }
        {
            use sequoia_openpgp::armor::{Kind, Writer};
            let mut w = Writer::new(&mut armored_first, Kind::PublicKey).unwrap();
            tpk_0.serialize(&mut w).unwrap();
            w.finalize().unwrap();
        }
        let mut post_data_first = String::from("keytext=");
        for enc in url::form_urlencoded::byte_serialize(&armored_first) {
            post_data_first.push_str(enc);
        }
        let mut post_data_both = String::from("keytext=");
        for enc in url::form_urlencoded::byte_serialize(&armored_both) {
            post_data_both.push_str(enc);
        }

        // Add!
        let response = client
            .post("/pks/add")
            .body(post_data_both.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // Check that there is no welcome mail (since we uploaded two)
        let welcome_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(welcome_mail.is_none());

        // Add the first again
        let response = client
            .post("/pks/add")
            .body(post_data_first.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let upload_mail_1 = pop_mail(filemail_into.as_path()).unwrap();
        assert!(upload_mail_1.is_none());

        check_mr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);

        assert_consistency(client.rocket());
    }
}
