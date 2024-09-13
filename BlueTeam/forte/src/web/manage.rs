use rocket::form::Form;
use rocket_i18n::I18n;

use crate::Result;

use gettext_macros::i18n;

use crate::counters;
use crate::database::{types::Email, types::Fingerprint, Database, KeyDatabase};
use crate::mail;
use crate::rate_limiter::RateLimiter;
use crate::tokens::{self, StatelessSerializable};
use crate::web::vks_web;
use crate::web::{MyResponse, RequestOrigin};

#[derive(Debug, Serialize, Deserialize)]
struct StatelessVerifyToken {
    fpr: Fingerprint,
}
impl StatelessSerializable for StatelessVerifyToken {}

mod templates {
    #[derive(Serialize)]
    pub struct ManageKey {
        pub key_fpr: String,
        pub key_link: String,
        pub base_uri: String,
        pub uid_status: Vec<ManageKeyUidStatus>,
        pub token: String,
    }

    #[derive(Serialize)]
    pub struct ManageLinkSent {
        pub address: String,
    }

    #[derive(Serialize)]
    pub struct ManageKeyUidStatus {
        pub address: String,
        pub published: bool,
    }
}

pub mod forms {
    #[derive(FromForm)]
    pub struct ManageRequest {
        pub search_term: String,
    }

    #[derive(FromForm)]
    pub struct ManageDelete {
        pub token: String,
        pub address: String,
    }
}

#[get("/manage")]
pub fn vks_manage(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("manage/manage", i18n, origin)
}

#[get("/manage/<token>")]
pub fn vks_manage_key(
    origin: RequestOrigin,
    db: &rocket::State<KeyDatabase>,
    i18n: I18n,
    token: String,
    token_service: &rocket::State<tokens::Service>,
) -> MyResponse {
    use crate::database::types::Fingerprint;
    use std::convert::TryFrom;
    if let Ok(StatelessVerifyToken { fpr }) = token_service.check(&token) {
        match db.lookup(&database::Query::ByFingerprint(fpr)) {
            Ok(Some(tpk)) => {
                let fp = Fingerprint::try_from(tpk.fingerprint()).unwrap();
                let mut emails: Vec<Email> = tpk
                    .userids()
                    .map(|u| u.userid().to_string().parse::<Email>())
                    .flatten()
                    .collect();
                emails.sort_unstable();
                emails.dedup();
                let uid_status = emails
                    .into_iter()
                    .map(|email| templates::ManageKeyUidStatus {
                        address: email.to_string(),
                        published: true,
                    })
                    .collect();
                let key_link = uri!(vks_web::search(q = fp.to_string())).to_string();
                let context = templates::ManageKey {
                    key_fpr: fp.to_string(),
                    key_link,
                    uid_status,
                    token,
                    base_uri: origin.get_base_uri().to_owned(),
                };
                MyResponse::ok("manage/manage_key", context, i18n, origin)
            }
            Ok(None) => MyResponse::not_found(
                Some("manage/manage"),
                Some(i18n!(i18n.catalog, "This link is invalid or expired")),
                i18n,
                origin,
            ),
            Err(e) => MyResponse::ise(e),
        }
    } else {
        MyResponse::not_found(
            Some("manage/manage"),
            Some(i18n!(i18n.catalog, "This link is invalid or expired")),
            i18n,
            origin,
        )
    }
}

#[post("/manage", data = "<request>")]
pub fn vks_manage_post(
    db: &rocket::State<KeyDatabase>,
    origin: RequestOrigin,
    mail_service: &rocket::State<mail::Service>,
    rate_limiter: &rocket::State<RateLimiter>,
    i18n: I18n,
    request: Form<forms::ManageRequest>,
    token_service: &rocket::State<tokens::Service>,
) -> MyResponse {
    use std::convert::TryInto;

    let email = match request.search_term.parse::<Email>() {
        Ok(email) => email,
        Err(_) => {
            return MyResponse::not_found(
                Some("manage/manage"),
                Some(i18n!(i18n.catalog, "Malformed address: {}"; &request.search_term)),
                i18n,
                origin,
            )
        }
    };

    let tpk = match db.lookup(&database::Query::ByEmail(email.clone())) {
        Ok(Some(tpk)) => tpk,
        Ok(None) => {
            return MyResponse::not_found(
                Some("manage/manage"),
                Some(i18n!(i18n.catalog, "No key for address: {}"; &request.search_term)),
                i18n,
                origin,
            )
        }
        Err(e) => return MyResponse::ise(e),
    };

    let email_exists = tpk
        .userids()
        .flat_map(|binding| binding.userid().to_string().parse::<Email>())
        .any(|candidate| candidate == email);

    if !email_exists {
        return MyResponse::ise(anyhow!("Internal error: address check failed!"));
    }

    if !rate_limiter.action_perform(format!("manage-{}", &email)) {
        return MyResponse::not_found(
            Some("manage/manage"),
            Some(i18n!(
                i18n.catalog,
                "A request has already been sent for this address recently."
            )),
            i18n,
            origin,
        );
    }

    let fpr: Fingerprint = tpk.fingerprint().try_into().unwrap();
    let fpr_text = fpr.to_string();
    let token = token_service.create(&StatelessVerifyToken { fpr });
    let link_path = uri!(vks_manage_key(token)).to_string();

    let base_uri = origin.get_base_uri();
    if let Err(e) = mail_service.send_manage_token(&i18n, base_uri, fpr_text, &email, &link_path) {
        return MyResponse::ise(e);
    }

    let ctx = templates::ManageLinkSent {
        address: email.to_string(),
    };
    MyResponse::ok("manage/manage_link_sent", ctx, i18n, origin)
}

#[post("/manage/unpublish", data = "<request>")]
pub fn vks_manage_unpublish(
    origin: RequestOrigin,
    db: &rocket::State<KeyDatabase>,
    i18n: I18n,
    token_service: &rocket::State<tokens::Service>,
    request: Form<forms::ManageDelete>,
) -> MyResponse {
    match vks_manage_unpublish_or_fail(origin, db, token_service, i18n, request) {
        Ok(response) => response,
        Err(e) => MyResponse::ise(e),
    }
}

pub fn vks_manage_unpublish_or_fail(
    origin: RequestOrigin,
    db: &rocket::State<KeyDatabase>,
    token_service: &rocket::State<tokens::Service>,
    i18n: I18n,
    request: Form<forms::ManageDelete>,
) -> Result<MyResponse> {
    let verify_token = token_service.check::<StatelessVerifyToken>(&request.token)?;
    let email = request.address.parse::<Email>()?;

    db.set_email_unpublished(&verify_token.fpr, &email)?;
    counters::inc_address_unpublished(&email);

    Ok(vks_manage_key(
        origin,
        db,
        i18n,
        request.token.to_owned(),
        token_service,
    ))
}
