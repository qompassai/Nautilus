use hyperx::header::{Charset, ContentDisposition, DispositionParam, DispositionType};
use rocket::figment::Figment;
use rocket::fs::NamedFile;
use rocket::http::{Header, Status};
use rocket::outcome::Outcome;
use rocket::request;
use rocket::response::status::Custom;
use rocket::response::{Responder, Response};
use rocket_dyn_templates::{Engines, Template};
use rocket_i18n::I18n;
use rocket_prometheus::PrometheusMetrics;

use gettext_macros::{compile_i18n, include_i18n};

use serde::Serialize;

use std::path::PathBuf;

use crate::counters;
use crate::i18n::I18NHelper;
use crate::i18n_helpers::describe_query_error;
use crate::mail;
use crate::rate_limiter::RateLimiter;
use crate::template_helpers::TemplateOverrides;
use crate::tokens;

use crate::database::types::Fingerprint;
use crate::database::{Database, KeyDatabase, Query};
use crate::Result;

use std::convert::TryInto;

mod debug_web;
mod hkp;
mod maintenance;
mod manage;
mod vks;
mod vks_api;
mod vks_web;
mod wkd;

use crate::web::maintenance::MaintenanceMode;

pub struct ForteTemplate(&'static str, serde_json::Value, I18n, RequestOrigin);

impl<'r> Responder<'r, 'static> for ForteTemplate {
    fn respond_to(
        self,
        req: &'r rocket::Request,
    ) -> std::result::Result<Response<'static>, Status> {
        let ForteTemplate(tmpl, ctx, i18n, origin) = self;

        let template_overrides: &TemplateOverrides = req
            .rocket()
            .state()
            .expect("TemplateOverrides must be in managed state");
        let template_override = template_overrides.get_template_override(i18n.lang, tmpl);
        let layout_context = templates::ForteLayout::new(ctx, i18n, origin);

        if let Some(template_override) = template_override {
            Template::render(template_override, layout_context)
        } else {
            Template::render(tmpl, layout_context)
        }
        .respond_to(req)
    }
}

#[derive(Responder)]
pub enum MyResponse {
    #[response(status = 200, content_type = "html")]
    Success(ForteTemplate),
    #[response(status = 200, content_type = "plain")]
    Plain(String),
    #[response(status = 200, content_type = "xml")]
    Xml(ForteTemplate),
    #[response(status = 200, content_type = "application/pgp-keys")]
    Key(String, Header<'static>),
    #[response(status = 200, content_type = "application/octet-stream")]
    WkdKey(Vec<u8>, Header<'static>),
    #[response(status = 500, content_type = "html")]
    ServerError(Template),
    #[response(status = 404, content_type = "html")]
    NotFound(ForteTemplate),
    #[response(status = 404, content_type = "html")]
    NotFoundPlain(String),
    #[response(status = 400, content_type = "html")]
    BadRequest(ForteTemplate),
    #[response(status = 400, content_type = "html")]
    BadRequestPlain(String),
    #[response(status = 501, content_type = "html")]
    NotImplementedPlain(String),
    #[response(status = 503, content_type = "html")]
    Maintenance(Template),
    #[response(status = 503, content_type = "json")]
    MaintenanceJson(serde_json::Value),
    #[response(status = 503, content_type = "plain")]
    MaintenancePlain(String),
}

impl MyResponse {
    pub fn ok(tmpl: &'static str, ctx: impl Serialize, i18n: I18n, origin: RequestOrigin) -> Self {
        let context_json = serde_json::to_value(ctx).unwrap();
        MyResponse::Success(ForteTemplate(tmpl, context_json, i18n, origin))
    }

    pub fn ok_bare(tmpl: &'static str, i18n: I18n, origin: RequestOrigin) -> Self {
        let context_json = serde_json::to_value(templates::Bare { dummy: () }).unwrap();
        MyResponse::Success(ForteTemplate(tmpl, context_json, i18n, origin))
    }

    pub fn xml(tmpl: &'static str, i18n: I18n, origin: RequestOrigin) -> Self {
        let context_json = serde_json::to_value(templates::Bare { dummy: () }).unwrap();
        MyResponse::Xml(ForteTemplate(tmpl, context_json, i18n, origin))
    }

    pub fn plain(s: String) -> Self {
        MyResponse::Plain(s)
    }

    pub fn key(armored_key: String, fp: &Fingerprint) -> Self {
        let content_disposition = Header::new(
            rocket::http::hyper::header::CONTENT_DISPOSITION.as_str(),
            ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![DispositionParam::Filename(
                    Charset::Us_Ascii,
                    None,
                    (fp.to_string() + ".asc").into_bytes(),
                )],
            }
            .to_string(),
        );
        MyResponse::Key(armored_key, content_disposition)
    }

    pub fn wkd(binary_key: Vec<u8>, wkd_hash: &str) -> Self {
        let content_disposition = Header::new(
            rocket::http::hyper::header::CONTENT_DISPOSITION.as_str(),
            ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![DispositionParam::Filename(
                    Charset::Us_Ascii,
                    None,
                    (wkd_hash.to_string() + ".pgp").into_bytes(),
                )],
            }
            .to_string(),
        );
        MyResponse::WkdKey(binary_key, content_disposition)
    }

    pub fn ise(e: anyhow::Error) -> Self {
        eprintln!("Internal error: {:?}", e);
        let ctx = templates::FiveHundred {
            internal_error: e.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            lang: "en".to_string(),
        };
        MyResponse::ServerError(Template::render("500", ctx))
    }

    pub fn bad_request(
        template: &'static str,
        e: anyhow::Error,
        i18n: I18n,
        origin: RequestOrigin,
    ) -> Self {
        let ctx = templates::Error {
            error: format!("{}", e),
        };
        let context_json = serde_json::to_value(ctx).unwrap();
        MyResponse::BadRequest(ForteTemplate(template, context_json, i18n, origin))
    }

    pub fn bad_request_plain(message: impl Into<String>) -> Self {
        MyResponse::BadRequestPlain(message.into())
    }

    pub fn not_found_plain(message: impl Into<String>) -> Self {
        MyResponse::NotFoundPlain(message.into())
    }

    pub fn not_implemented_plain(message: impl Into<String>) -> Self {
        MyResponse::NotImplementedPlain(message.into())
    }

    pub fn not_found(
        tmpl: Option<&'static str>,
        message: impl Into<Option<String>>,
        i18n: I18n,
        origin: RequestOrigin,
    ) -> Self {
        let ctx = templates::Error {
            error: message.into().unwrap_or_else(|| "Key not found".to_owned()),
        };
        let context_json = serde_json::to_value(ctx).unwrap();
        MyResponse::NotFound(ForteTemplate(
            tmpl.unwrap_or("index"),
            context_json,
            i18n,
            origin,
        ))
    }
}

mod templates {
    use super::{I18n, RequestOrigin};

    #[derive(Serialize)]
    pub struct FiveHundred {
        pub internal_error: String,
        pub commit: String,
        pub version: String,
        pub lang: String,
    }

    #[derive(Serialize)]
    pub struct ForteLayout<T: serde::Serialize> {
        pub error: Option<String>,
        pub commit: String,
        pub version: String,
        pub base_uri: String,
        pub lang: String,
        pub htmldir: String,
        pub htmlclass: String,
        pub page: T,
    }

    #[derive(Serialize)]
    pub struct Error {
        pub error: String,
    }

    #[derive(Serialize)]
    pub struct Bare {
        // Dummy value to make sure {{#with page}} always passes
        pub dummy: (),
    }

    impl<T: serde::Serialize> ForteLayout<T> {
        pub fn new(page: T, i18n: I18n, origin: RequestOrigin) -> Self {
            let is_rtl = (i18n.lang) == "ar";
            Self {
                error: None,
                version: env!("CARGO_PKG_VERSION").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
                base_uri: origin.get_base_uri().to_string(),
                page,
                lang: i18n.lang.to_string(),
                htmldir: if is_rtl {
                    "rtl".to_owned()
                } else {
                    "ltr".to_owned()
                },
                htmlclass: if is_rtl {
                    "rtl".to_owned()
                } else {
                    "".to_owned()
                },
            }
        }
    }
}

pub struct ForteState {
    /// Assets directory, mounted to /assets, served by forte or nginx
    assets_dir: PathBuf,

    /// XXX
    base_uri: String,
    base_uri_onion: String,
}

#[derive(Debug)]
pub enum RequestOrigin {
    Direct(String),
    OnionService(String),
}

#[async_trait]
impl<'r> request::FromRequest<'r> for RequestOrigin {
    type Error = ();

    async fn from_request(
        request: &'r request::Request<'_>,
    ) -> request::Outcome<Self, Self::Error> {
        let forte_state = request.rocket().state::<ForteState>().unwrap();
        let result = match request.headers().get("x-is-onion").next() {
            Some(_) => RequestOrigin::OnionService(forte_state.base_uri_onion.clone()),
            None => RequestOrigin::Direct(forte_state.base_uri.clone()),
        };
        Outcome::Success(result)
    }
}

impl RequestOrigin {
    fn get_base_uri(&self) -> &str {
        match self {
            RequestOrigin::Direct(uri) => uri.as_str(),
            RequestOrigin::OnionService(uri) => uri.as_str(),
        }
    }
}

pub fn key_to_response_plain(
    db: &rocket::State<KeyDatabase>,
    i18n: I18n,
    query: Query,
) -> MyResponse {
    if query.is_invalid() {
        return MyResponse::bad_request_plain(describe_query_error(&i18n, &query));
    }

    let fp = if let Some(fp) = db.lookup_primary_fingerprint(&query) {
        fp
    } else {
        return MyResponse::not_found_plain(describe_query_error(&i18n, &query));
    };

    match db.by_fpr(&fp) {
        Some(armored) => MyResponse::key(armored, &fp),
        None => MyResponse::not_found_plain(describe_query_error(&i18n, &query)),
    }
}

#[get("/assets/<file..>")]
async fn files(file: PathBuf, state: &rocket::State<ForteState>) -> Option<NamedFile> {
    NamedFile::open(state.assets_dir.join(file)).await.ok()
}

#[get("/")]
fn root(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("index", i18n, origin)
}

#[get("/about")]
fn about(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("about/about", i18n, origin)
}

#[get("/about/news")]
fn news(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("about/news", i18n, origin)
}

#[get("/atom.xml")]
fn news_atom(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::xml("atom", i18n, origin)
}

#[get("/about/faq")]
fn faq(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("about/faq", i18n, origin)
}

#[get("/about/usage")]
fn usage(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("about/usage", i18n, origin)
}

#[get("/about/privacy")]
fn privacy(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("about/privacy", i18n, origin)
}

#[get("/about/api")]
fn apidoc(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("about/api", i18n, origin)
}

#[get("/about/stats")]
fn stats(origin: RequestOrigin, i18n: I18n) -> MyResponse {
    MyResponse::ok_bare("about/stats", i18n, origin)
}

#[get("/errors/<code>/<template>")]
fn errors(
    i18n: I18n,
    origin: RequestOrigin,
    code: u16,
    template: String,
) -> std::result::Result<Custom<Template>, &'static str> {
    if !template
        .chars()
        .all(|x| x == '-' || char::is_ascii_alphabetic(&x))
    {
        return Err("bad request");
    }
    let status_code = Status::from_code(code).ok_or("bad request")?;
    let response_body = Template::render(
        format!("errors/{}-{}", code, template),
        templates::ForteLayout::new(templates::Bare { dummy: () }, i18n, origin),
    );
    Ok(Custom(status_code, response_body))
}

pub fn serve() -> Result<rocket::Rocket<rocket::Build>> {
    rocket_factory(rocket::build())
}

compile_i18n!();

// The include_i18n macro must be called after compile_i18n, which must be called after i18n macros
// *in compilation order*. We use a helper function here to make this order consistent.
pub fn get_i18n() -> Vec<(&'static str, gettext::Catalog)> {
    include_i18n!()
}

fn rocket_factory(
    mut rocket: rocket::Rocket<rocket::Build>,
) -> Result<rocket::Rocket<rocket::Build>> {
    let routes = routes![
        // infra
        root,
        about,
        news,
        news_atom,
        privacy,
        apidoc,
        faq,
        usage,
        files,
        stats,
        errors,
        // VKSv1
        vks_api::vks_v1_by_email,
        vks_api::vks_v1_by_fingerprint,
        vks_api::vks_v1_by_keyid,
        vks_api::upload_json,
        vks_api::upload_fallback,
        vks_api::request_verify_json,
        vks_api::request_verify_fallback,
        // User interaction.
        vks_web::search,
        vks_web::upload,
        vks_web::upload_post_form,
        vks_web::upload_post_form_data,
        vks_web::request_verify_form,
        vks_web::request_verify_form_data,
        vks_web::verify_confirm,
        vks_web::verify_confirm_form,
        vks_web::quick_upload,
        vks_web::quick_upload_proceed,
        // Debug
        debug_web::debug_info,
        // HKP
        hkp::pks_lookup,
        hkp::pks_add_form,
        hkp::pks_add_form_data,
        hkp::pks_internal_index,
        // WKD
        wkd::wkd_policy,
        wkd::wkd_query,
        // Manage
        manage::vks_manage,
        manage::vks_manage_key,
        manage::vks_manage_post,
        manage::vks_manage_unpublish,
        // Maintenance error page
        maintenance::maintenance_error_web,
        maintenance::maintenance_error_json,
        maintenance::maintenance_error_plain,
    ];

    let figment = rocket.figment();
    let db_service = configure_db_service(figment)?;
    let forte_state = configure_forte_state(figment)?;
    let stateful_token_service = configure_stateful_token_service(figment)?;
    let stateless_token_service = configure_stateless_token_service(figment)?;
    let mail_service = configure_mail_service(figment)?;
    let rate_limiter = configure_rate_limiter(figment)?;
    let maintenance_mode = configure_maintenance_mode(figment)?;
    let localized_template_list = configure_localized_template_list(figment)?;
    println!("{:?}", localized_template_list);

    let prometheus = configure_prometheus(figment);

    rocket = rocket
        .attach(Template::custom(|engines: &mut Engines| {
            let i18ns = get_i18n();
            let i18n_helper = I18NHelper::new(i18ns);
            engines
                .handlebars
                .register_helper("text", Box::new(i18n_helper));
        }))
        .attach(maintenance_mode)
        .manage(get_i18n())
        .manage(forte_state)
        .manage(stateless_token_service)
        .manage(stateful_token_service)
        .manage(mail_service)
        .manage(db_service)
        .manage(rate_limiter)
        .manage(localized_template_list)
        .mount("/", routes);

    if let Some(prometheus) = prometheus {
        rocket = rocket
            .attach(prometheus.clone())
            .mount("/metrics", prometheus);
    }

    Ok(rocket)
}

fn configure_prometheus(config: &Figment) -> Option<PrometheusMetrics> {
    if !config.extract_inner("enable_prometheus").unwrap_or(false) {
        return None;
    }
    let prometheus = PrometheusMetrics::new();
    counters::register_counters(prometheus.registry());
    Some(prometheus)
}

fn configure_db_service(config: &Figment) -> Result<KeyDatabase> {
    let keys_internal_dir: PathBuf = config.extract_inner("keys_internal_dir")?;
    let keys_external_dir: PathBuf = config.extract_inner("keys_external_dir")?;
    let tmp_dir: PathBuf = config.extract_inner("tmp_dir")?;

    let fs_db = KeyDatabase::new(keys_internal_dir, keys_external_dir, tmp_dir)?;
    Ok(fs_db)
}

fn configure_forte_state(config: &Figment) -> Result<ForteState> {
    let assets_dir: PathBuf = config.extract_inner("assets_dir")?;

    // State
    let base_uri: String = config.extract_inner("base-URI")?;
    let base_uri_onion = config
        .extract_inner::<String>("base-URI-Onion")
        .unwrap_or_else(|_| base_uri.clone());
    Ok(ForteState {
        assets_dir,
        base_uri,
        base_uri_onion,
    })
}

fn configure_stateful_token_service(config: &Figment) -> Result<database::StatefulTokens> {
    let token_dir: PathBuf = config.extract_inner("token_dir")?;
    database::StatefulTokens::new(token_dir)
}

fn configure_stateless_token_service(config: &Figment) -> Result<tokens::Service> {
    let secret: String = config.extract_inner("token_secret")?;
    let validity: u64 = config.extract_inner("token_validity")?;
    Ok(tokens::Service::init(&secret, validity))
}

fn configure_mail_service(config: &Figment) -> Result<mail::Service> {
    // Mail service
    let email_template_dir: PathBuf = config.extract_inner("email_template_dir")?;

    let base_uri: String = config.extract_inner("base-URI")?;
    let from: String = config.extract_inner("from")?;

    let filemail_into: Option<PathBuf> = config.extract_inner::<PathBuf>("filemail_into").ok();

    if let Some(path) = filemail_into {
        mail::Service::filemail(&from, &base_uri, &email_template_dir, &path)
    } else {
        mail::Service::sendmail(&from, &base_uri, &email_template_dir)
    }
}

fn configure_rate_limiter(config: &Figment) -> Result<RateLimiter> {
    let timeout_secs: i32 = config.extract_inner("mail_rate_limit").unwrap_or(60);
    let timeout_secs = timeout_secs.try_into()?;
    Ok(RateLimiter::new(timeout_secs))
}

fn configure_localized_template_list(config: &Figment) -> Result<TemplateOverrides> {
    let template_dir: PathBuf = config.extract_inner("template_dir")?;
    TemplateOverrides::load(&template_dir, "localized")
}

fn configure_maintenance_mode(config: &Figment) -> Result<MaintenanceMode> {
    let maintenance_file: PathBuf = config
        .extract_inner("maintenance_file")
        .unwrap_or_else(|_| PathBuf::from("maintenance"));
    Ok(MaintenanceMode::new(maintenance_file))
}

#[cfg(test)]
pub mod tests {
    use regex;
    use rocket::http::ContentType;
    use rocket::http::Header;
    use rocket::http::Status;
    use rocket::local::blocking::{Client, LocalResponse};
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::{tempdir, TempDir};

    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::serialize::Serialize;
    use sequoia_openpgp::Cert;

    use std::time::SystemTime;

    use mail::pop_mail;

    use super::*;

    /// Fake base URI to use in tests.
    const BASE_URI: &str = "http://local.connection";
    const BASE_URI_ONION: &str = "http://local.connection.onion";

    pub fn build_cert(name: &str) -> Cert {
        let (tpk, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .add_userid(name)
            .generate()
            .unwrap();
        tpk
    }

    /// Creates a configuration and empty state dir for testing purposes.
    ///
    /// Note that you need to keep the returned TempDir alive for the
    /// duration of your test.  To debug the test, mem::forget it to
    /// prevent cleanup.
    pub fn configuration() -> Result<(TempDir, rocket::figment::Figment)> {
        let root = tempdir()?;
        let filemail = root.path().join("filemail");
        ::std::fs::create_dir_all(&filemail)?;

        let base_dir: PathBuf = root.path().into();

        let config = rocket::Config::figment()
            .select("staging")
            .merge(("root", root.path()))
            .merge((
                "template_dir",
                ::std::env::current_dir()
                    .unwrap()
                    .join("dist/templates")
                    .to_str()
                    .unwrap(),
            ))
            .merge((
                "email_template_dir",
                ::std::env::current_dir()
                    .unwrap()
                    .join("dist/email-templates")
                    .to_str()
                    .unwrap(),
            ))
            .merge((
                "assets_dir",
                ::std::env::current_dir()
                    .unwrap()
                    .join("dist/assets")
                    .to_str()
                    .unwrap(),
            ))
            .merge((
                "keys_internal_dir",
                base_dir.join("keys_internal").to_str().unwrap(),
            ))
            .merge((
                "keys_external_dir",
                base_dir.join("keys_external").to_str().unwrap(),
            ))
            .merge(("tmp_dir", base_dir.join("tmp").to_str().unwrap()))
            .merge(("token_dir", base_dir.join("tokens").to_str().unwrap()))
            .merge((
                "maintenance_file",
                base_dir.join("maintenance").to_str().unwrap(),
            ))
            .merge(("base-URI", BASE_URI))
            .merge(("base-URI-Onion", BASE_URI_ONION))
            .merge(("from", "from@example.com"))
            .merge(("token_secret", "forte"))
            .merge(("token_validity", 3600u64))
            .merge((
                "filemail_into",
                filemail
                    .into_os_string()
                    .into_string()
                    .expect("path is valid UTF8"),
            ));
        Ok((root, config))
    }

    pub fn client() -> Result<(TempDir, Client)> {
        let (tmpdir, config) = configuration()?;
        let rocket = rocket_factory(rocket::custom(config))?;
        Ok((tmpdir, Client::untracked(rocket)?))
    }

    pub fn assert_consistency(rocket: &rocket::Rocket<rocket::Orbit>) {
        let db = rocket.state::<KeyDatabase>().unwrap();
        db.check_consistency().unwrap();
    }

    #[test]
    fn about_translation() {
        let (_tmpdir, config) = configuration().unwrap();
        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::untracked(rocket).expect("valid rocket instance");

        // Check that we see the landing page.
        let response = client
            .get("/about")
            .header(Header::new("Accept-Language", "de"))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        // TODO check translation
        assert!(response.into_string().unwrap().contains("Forte"));
    }

    #[test]
    fn basics() {
        let (_tmpdir, config) = configuration().unwrap();
        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::untracked(rocket).expect("valid rocket instance");

        // Check that we see the landing page.
        let response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.into_string().unwrap().contains("Forte"));

        // Check that we see the privacy policy.
        let response = client.get("/about").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response
            .into_string()
            .unwrap()
            .contains("distribution and discovery"));

        // Check that we see the privacy policy.
        let response = client.get("/about/privacy").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.into_string().unwrap().contains("Public Key Data"));

        // Check that we see the API docs.
        let response = client.get("/about/api").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.into_string().unwrap().contains("/vks/v1/by-keyid"));

        // Check that we see the upload form.
        let response = client.get("/upload").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.into_string().unwrap().contains("upload"));

        // Check that we see the deletion form.
        let response = client.get("/manage").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response
            .into_string()
            .unwrap()
            .contains("any verified email address"));

        assert_consistency(client.rocket());
    }

    #[test]
    fn maintenance() {
        let (tmpdir, client) = client().unwrap();

        let maintenance_path = tmpdir.path().join("maintenance");
        let mut file = File::create(&maintenance_path).unwrap();
        file.write_all(b"maintenance-message").unwrap();

        // Check that endpoints return a maintenance message
        check_maintenance(&client, "/upload", ContentType::HTML);
        check_maintenance(&client, "/manage", ContentType::HTML);
        check_maintenance(&client, "/verify", ContentType::HTML);
        check_maintenance(&client, "/pks/add", ContentType::Plain);
        check_maintenance(&client, "/vks/v1/upload", ContentType::JSON);
        check_maintenance(&client, "/vks/v1/request-verify", ContentType::JSON);

        // Extra check for the shortcut "PUT" endpoint
        let response = client.put("/").dispatch();
        assert_eq!(response.status(), Status::ServiceUnavailable);
        assert_eq!(response.content_type(), Some(ContentType::Plain));
        assert!(response
            .into_string()
            .unwrap()
            .contains("maintenance-message"));

        fs::remove_file(&maintenance_path).unwrap();
        // Check that we see the upload form.
        let response = client.get("/upload").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(!response
            .into_string()
            .unwrap()
            .contains("maintenance-message"));
    }

    fn check_maintenance(client: &Client, uri: &str, content_type: ContentType) {
        let response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::ServiceUnavailable);
        assert_eq!(response.content_type(), Some(content_type));
        assert!(response
            .into_string()
            .unwrap()
            .contains("maintenance-message"));
    }

    #[test]
    fn upload_verify_single() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate a key and upload it.
        let tpk = build_cert("foo@invalid.example.com");

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();
        let token = vks_publish_submit_get_token(&client, &tpk_serialized);

        // Prior to email confirmation, we should not be able to look
        // it up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // And check that we can get it back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 0);

        // Check the verification link
        check_verify_link(&client, &token, "foo@invalid.example.com", "");

        // Now check for the verification mail.
        check_mails_and_verify_email(&client, filemail_into.as_path());

        // Now lookups using the mail address should work.
        check_responses_by_email(&client, "foo@invalid.example.com", &tpk, 1);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 1);

        // Request deletion of the binding.
        vks_manage(&client, "foo@invalid.example.com");

        // Confirm deletion.
        check_mails_and_confirm_deletion(
            &client,
            filemail_into.as_path(),
            "foo@invalid.example.com",
        );

        // Now, we should no longer be able to look it up by email
        // address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // But lookup by fingerprint should still work.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 0);

        assert_consistency(client.rocket());
    }

    #[test]
    fn upload_verify_lang() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate a key and upload it.
        let tpk = build_cert("foo@invalid.example.com");

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();
        let token = vks_publish_submit_get_token(&client, &tpk_serialized);

        check_verify_link(&client, &token, "foo@invalid.example.com", "de");
        let mail_content = pop_mail(&filemail_into).unwrap().unwrap();
        assert!(mail_content.contains("Dies ist eine automatisierte Nachricht"));
        assert!(mail_content.contains("Subject: =?utf-8?q?Best=C3=A4tige?= foo@invalid.example.com\r\n\t=?utf-8?q?f=C3=BCr?= deinen =?utf-8?q?Schl=C3=BCssel?= auf local.connection"));
    }

    #[test]
    fn upload_two() {
        let (_tmpdir, config) = configuration().unwrap();

        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::untracked(rocket).expect("valid rocket instance");

        // Generate two keys and upload them.
        let tpk_0 = build_cert("foo@invalid.example.com");
        let tpk_1 = build_cert("bar@invalid.example.com");

        let mut tpk_serialized = Vec::new();
        tpk_0.serialize(&mut tpk_serialized).unwrap();
        tpk_1.serialize(&mut tpk_serialized).unwrap();
        vks_publish_submit_multiple(&client, &tpk_serialized);

        // Prior to email confirmation, we should not be able to look
        // them up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");
        check_null_responses_by_email(&client, "bar@invalid.example.com");

        // And check that we can get them back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);
    }

    #[test]
    fn upload_verify_two() {
        let (tmpdir, config) = configuration().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::untracked(rocket).expect("valid rocket instance");

        // Generate two keys and upload them.
        let tpk_1 = build_cert("foo@invalid.example.com");
        let tpk_2 = build_cert("bar@invalid.example.com");

        let mut tpk_serialized_1 = Vec::new();
        tpk_1.serialize(&mut tpk_serialized_1).unwrap();
        let token_1 = vks_publish_submit_get_token(&client, &tpk_serialized_1);

        let mut tpk_serialized_2 = Vec::new();
        tpk_2.serialize(&mut tpk_serialized_2).unwrap();
        let token_2 = vks_publish_json_get_token(&client, &tpk_serialized_2);

        // Prior to email confirmation, we should not be able to look
        // them up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");
        check_null_responses_by_email(&client, "bar@invalid.example.com");

        // And check that we can get them back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_2, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_2, 0);

        // Check the verification link
        check_verify_link(&client, &token_1, "foo@invalid.example.com", "");
        check_verify_link_json(&client, &token_2, "bar@invalid.example.com");

        // Now check for the verification mails.
        check_mails_and_verify_email(&client, &filemail_into);
        check_mails_and_verify_email(&client, &filemail_into);

        // Now lookups using the mail address should work.
        check_responses_by_email(&client, "foo@invalid.example.com", &tpk_1, 1);
        check_responses_by_email(&client, "bar@invalid.example.com", &tpk_2, 1);

        // Request deletion of the bindings.
        vks_manage(&client, "foo@invalid.example.com");
        check_mails_and_confirm_deletion(&client, &filemail_into, "foo@invalid.example.com");
        vks_manage(&client, "bar@invalid.example.com");
        check_mails_and_confirm_deletion(&client, &filemail_into, "bar@invalid.example.com");

        // Now, we should no longer be able to look it up by email
        // address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");
        check_null_responses_by_email(&client, "bar@invalid.example.com");

        // But lookup by fingerprint should still work.
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_2, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_2, 0);

        assert_consistency(client.rocket());
    }

    #[test]
    fn upload_no_key() {
        let (_tmpdir, client) = client().unwrap();
        let response = vks_publish_submit_response(&client, b"");
        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn upload_verify_onion() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate a key and upload it.
        let tpk = build_cert("foo@invalid.example.com");

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();
        let token = vks_publish_submit_get_token(&client, &tpk_serialized);

        // Check the verification link
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", &token)
            .append_pair("address", "foo@invalid.example.com")
            .finish();

        let response = client
            .post("/upload/request-verify")
            .header(ContentType::Form)
            .header(Header::new("X-Is-Onion", "true"))
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // Now check for the verification mail.
        let pattern = format!("{}(/verify/[^ \t\n]*)", BASE_URI_ONION);
        let confirm_uri = pop_mail_capture_pattern(&filemail_into, &pattern);

        let response = client.get(&confirm_uri).dispatch();
        assert_eq!(response.status(), Status::Ok);

        assert_consistency(client.rocket());
    }

    #[test]
    fn upload_curl_shortcut() {
        let (_tmpdir, client) = client().unwrap();

        let tpk = build_cert("foo@invalid.example.com");

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();

        let _token = vks_publish_shortcut_get_token(&client, &tpk_serialized);

        check_mr_responses_by_fingerprint(&client, &tpk, 0);
        check_null_responses_by_email(&client, "foo@invalid.example.com");
    }

    #[test]
    fn search_invalid() {
        let (_tmpdir, client) = client().unwrap();
        check_response(
            &client,
            "/search?q=0x1234abcd",
            Status::BadRequest,
            "not supported",
        );
        check_response(
            &client,
            "/search?q=1234abcd",
            Status::BadRequest,
            "not supported",
        );
        check_response(
            &client,
            "/pks/lookup?op=get&search=0x1234abcd",
            Status::BadRequest,
            "not supported",
        );
        check_response(
            &client,
            "/pks/lookup?op=get&search=1234abcd",
            Status::BadRequest,
            "not supported",
        );
    }
    #[test]
    fn wkd_policy() {
        let (_tmpdir, client) = client().unwrap();
        check_response(
            &client,
            "/.well-known/openpgpkey/example.org/policy",
            Status::Ok,
            "",
        );
    }

    /// Asserts that the given URI 404s.
    pub fn check_null_response(client: &Client, uri: &str) {
        let response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::NotFound);
    }

    /// Asserts that lookups by the given email 404.
    pub fn check_null_responses_by_email(client: &Client, addr: &str) {
        check_null_response(client, &format!("/vks/v1/by-email/{}", addr));
        check_null_response(client, &format!("/pks/lookup?op=get&search={}", addr));
        check_null_response(
            client,
            &format!("/pks/lookup?op=get&options=mr&search={}", addr),
        );

        let (wkd_hash, domain) = crate::database::wkd::encode_wkd(addr).unwrap();
        check_null_response(
            client,
            &format!("/.well-known/openpgpkey/{}/hu/{}", domain, wkd_hash),
        );
    }

    /// Asserts that lookups by the given email are successful.
    pub fn check_responses_by_email(client: &Client, addr: &str, tpk: &Cert, nr_uids: usize) {
        check_mr_response(client, &format!("/vks/v1/by-email/{}", addr), tpk, nr_uids);
        check_mr_response(
            client,
            &format!("/vks/v1/by-email/{}", addr.replace("@", "%40")),
            tpk,
            nr_uids,
        );
        check_mr_response(
            client,
            &format!("/pks/lookup?op=get&options=mr&search={}", addr),
            tpk,
            nr_uids,
        );
        check_mr_response(
            client,
            &format!(
                "/pks/lookup?op=get&options=mr&search={}",
                addr.replace("@", "%40")
            ),
            tpk,
            nr_uids,
        );
        check_hr_response(client, &format!("/search?q={}", addr), tpk, nr_uids);
        check_hr_response_onion(client, &format!("/search?q={}", addr), tpk, nr_uids);

        let (wkd_hash, domain) = crate::database::wkd::encode_wkd(addr).unwrap();
        check_wkd_response(
            client,
            &format!("/.well-known/openpgpkey/{}/hu/{}", domain, wkd_hash),
            tpk,
            nr_uids,
        );
    }

    /// Asserts that the given URI returns a Cert matching the given
    /// one, with the given number of userids.
    pub fn check_mr_response(client: &Client, uri: &str, tpk: &Cert, nr_uids: usize) {
        let response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.content_type(),
            Some(ContentType::new("application", "pgp-keys"))
        );
        let body = response.into_string().unwrap();
        assert!(body.contains("END PGP PUBLIC KEY BLOCK"));
        let tpk_ = Cert::from_bytes(body.as_bytes()).unwrap();
        assert_eq!(tpk.fingerprint(), tpk_.fingerprint());
        assert_eq!(
            tpk.keys()
                .map(|skb| skb.key().fingerprint())
                .collect::<Vec<_>>(),
            tpk_.keys()
                .map(|skb| skb.key().fingerprint())
                .collect::<Vec<_>>()
        );
        assert_eq!(tpk_.userids().count(), nr_uids);
    }

    // it's a rather "reverse implementation" style test.. can we do better?
    /// Asserts that the given URI returns a correct hkp "index"
    /// response for the given Cert.
    pub fn check_index_response(client: &Client, uri: &str, tpk: &Cert) {
        let response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.content_type(),
            Some(ContentType::new("text", "plain"))
        );
        let body = response.into_string().unwrap();

        assert!(body.contains("info:1:1"));
        let primary_fpr = tpk.fingerprint().to_hex();
        let algo: u8 = tpk.primary_key().pk_algo().into();
        assert!(body.contains(&format!("pub:{}:{}:", primary_fpr, algo)));

        let creation_time = tpk
            .primary_key()
            .creation_time()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(body.contains(&format!(":{}:", creation_time)));
    }

    /// Asserts that we can get the given Cert back using the various
    /// by-fingerprint or by-keyid lookup mechanisms.
    pub fn check_mr_responses_by_fingerprint(client: &Client, tpk: &Cert, nr_uids: usize) {
        let fp = tpk.fingerprint().to_hex();
        let keyid = sequoia_openpgp::KeyID::from(tpk.fingerprint()).to_hex();

        check_mr_response(client, &format!("/vks/v1/by-keyid/{}", keyid), tpk, nr_uids);
        check_mr_response(
            client,
            &format!("/vks/v1/by-fingerprint/{}", fp),
            tpk,
            nr_uids,
        );
        check_mr_response(
            client,
            &format!("/pks/lookup?op=get&options=mr&search={}", fp),
            tpk,
            nr_uids,
        );
        check_mr_response(
            client,
            &format!("/pks/lookup?op=get&options=mr&search=0x{}", fp),
            tpk,
            nr_uids,
        );
        check_mr_response(
            client,
            &format!("/pks/lookup?op=get&options=mr&search={}", keyid),
            tpk,
            nr_uids,
        );
        check_mr_response(
            client,
            &format!("/pks/lookup?op=get&options=mr&search=0x{}", keyid),
            tpk,
            nr_uids,
        );
        check_mr_response(
            client,
            &format!("/pks/lookup?op=get&search=0x{}", keyid),
            tpk,
            nr_uids,
        );

        check_index_response(client, &format!("/pks/lookup?op=index&search={}", fp), tpk);
    }

    /// Asserts that the given URI contains the search string.
    pub fn check_response(client: &Client, uri: &str, status: Status, needle: &str) {
        let response = client.get(uri).dispatch();
        assert_eq!(response.status(), status);
        let body = response.into_string().unwrap();
        println!("{}", body);
        assert!(body.contains(needle));
    }

    /// Asserts that the given URI returns human readable response
    /// page that contains a URI pointing to the Cert.
    pub fn check_hr_response(client: &Client, uri: &str, tpk: &Cert, nr_uids: usize) {
        let response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        let body = response.into_string().unwrap();
        assert!(body.contains("found"));
        assert!(body.contains(&tpk.fingerprint().to_hex()));

        // Extract the links.
        let link_re = regex::Regex::new(&format!("{}(/vks/[^ \t\n\"<]*)", BASE_URI)).unwrap();
        let mut n = 0;
        for link in link_re.captures_iter(&body) {
            check_mr_response(client, link.get(1).unwrap().as_str(), tpk, nr_uids);
            n += 1;
        }
        assert!(n > 0);
    }

    /// Asserts that the given URI returns human readable response
    /// page that contains an onion URI pointing to the Cert.
    pub fn check_hr_response_onion(client: &Client, uri: &str, tpk: &Cert, _nr_uids: usize) {
        let response = client
            .get(uri)
            .header(Header::new("X-Is-Onion", "true"))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        assert!(body.contains("found"));
        assert!(body.contains(&tpk.fingerprint().to_hex()));

        // Extract the links.
        let link_re = regex::Regex::new(&format!("{}(/vks/[^ \t\n\"<]*)", BASE_URI_ONION)).unwrap();
        assert!(link_re.is_match(&body));
    }

    /// Asserts that we can get the given Cert back using the various
    /// by-fingerprint or by-keyid lookup mechanisms.
    pub fn check_hr_responses_by_fingerprint(client: &Client, tpk: &Cert, nr_uids: usize) {
        let fp = tpk.fingerprint().to_hex();
        let keyid = sequoia_openpgp::KeyID::from(tpk.fingerprint()).to_hex();

        check_hr_response(client, &format!("/search?q={}", fp), tpk, nr_uids);
        check_hr_response(client, &format!("/search?q=0x{}", fp), tpk, nr_uids);
        check_hr_response(client, &format!("/search?q={}", keyid), tpk, nr_uids);
        check_hr_response(client, &format!("/search?q=0x{}", keyid), tpk, nr_uids);
    }

    /// Asserts that the given URI returns correct WKD response with a Cert
    /// matching the given one, with the given number of userids.
    pub fn check_wkd_response(client: &Client, uri: &str, tpk: &Cert, nr_uids: usize) {
        let response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.content_type(),
            Some(ContentType::new("application", "octet-stream"))
        );
        let body = response.into_bytes().unwrap();
        let tpk_ = Cert::from_bytes(&body).unwrap();
        assert_eq!(tpk.fingerprint(), tpk_.fingerprint());
        assert_eq!(
            tpk.keys()
                .map(|skb| skb.key().fingerprint())
                .collect::<Vec<_>>(),
            tpk_.keys()
                .map(|skb| skb.key().fingerprint())
                .collect::<Vec<_>>()
        );
        assert_eq!(tpk_.userids().count(), nr_uids);
    }

    fn check_verify_link(client: &Client, token: &str, address: &str, lang: &'static str) {
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("address", address)
            .finish();

        let response = client
            .post("/upload/request-verify")
            .header(ContentType::Form)
            .header(Header::new("Accept-Language", lang))
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    fn check_verify_link_json(client: &Client, token: &str, address: &str) {
        let json = format!(r#"{{"token":"{}","addresses":["{}"]}}"#, token, address);

        let response = client
            .post("/vks/v1/request-verify")
            .header(ContentType::JSON)
            .body(json.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert!(response.into_string().unwrap().contains("pending"));
    }

    fn check_mails_and_verify_email(client: &Client, filemail_path: &Path) {
        let pattern = format!("{}(/verify/[^ \t\n]*)", BASE_URI);
        let confirm_uri = pop_mail_capture_pattern(filemail_path, &pattern);

        let response = client.post(&confirm_uri).dispatch();
        assert_eq!(response.status(), Status::Ok);

        let response_second = client.post(&confirm_uri).dispatch();
        assert_eq!(response_second.status(), Status::BadRequest);
        assert!(response_second
            .into_string()
            .unwrap()
            .contains("already been verified"));
    }

    fn check_mails_and_confirm_deletion(client: &Client, filemail_path: &Path, address: &str) {
        let pattern = format!("{}/manage/([^ \t\n]*)", BASE_URI);
        let token = pop_mail_capture_pattern(filemail_path, &pattern);
        vks_manage_delete(client, &token, address);
    }

    fn pop_mail_capture_pattern(filemail_path: &Path, pattern: &str) -> String {
        let mail_content = pop_mail(filemail_path).unwrap().unwrap();

        let capture_re = regex::bytes::Regex::new(pattern).unwrap();
        let capture_content = capture_re
            .captures(mail_content.as_ref())
            .unwrap()
            .get(1)
            .unwrap()
            .as_bytes();
        String::from_utf8_lossy(capture_content).to_string()
    }

    fn vks_publish_submit_multiple(client: &Client, data: &[u8]) {
        let response = vks_publish_submit_response(client, data);
        let status = response.status();
        let response_body = response.into_string().unwrap();

        assert_eq!(status, Status::Ok);
        assert!(response_body.contains("you must upload them individually"));
    }

    fn vks_publish_submit_get_token(client: &Client, data: &[u8]) -> String {
        let response = vks_publish_submit_response(client, data);
        let status = response.status();
        let response_body = response.into_string().unwrap();

        let pattern = "name=\"token\" value=\"([^\"]*)\"";
        let capture_re = regex::bytes::Regex::new(pattern).unwrap();
        let capture_content = capture_re
            .captures(response_body.as_bytes())
            .unwrap()
            .get(1)
            .unwrap()
            .as_bytes();
        let token = String::from_utf8_lossy(capture_content).to_string();

        assert_eq!(status, Status::Ok);
        token
    }

    fn vks_publish_submit_response<'a>(client: &'a Client, data: &[u8]) -> LocalResponse<'a> {
        let ct = ContentType::with_params(
            "multipart",
            "form-data",
            (
                "boundary",
                "---------------------------14733842173518794281682249499",
            ),
        );

        let header = b"-----------------------------14733842173518794281682249499\r\n\
              Content-Disposition: form-data; name=\"csrf\"\r\n\
              \r\n\
              \r\n\
              -----------------------------14733842173518794281682249499\r\n\
              Content-Disposition: form-data; name=\"keytext\"; filename=\".k\"\r\n\
              Content-Type: application/octet-stream\r\n\
              \r\n";
        let footer = b"\r\n-----------------------------14733842173518794281682249499--";

        let mut body = Vec::new();
        body.extend_from_slice(header);
        body.extend_from_slice(data);
        body.extend_from_slice(footer);
        client
            .post("/upload/submit")
            .header(ct)
            .body(&body[..])
            .dispatch()
    }

    fn vks_publish_shortcut_get_token(client: &Client, data: &[u8]) -> String {
        let response = client.put("/").body(data).dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response_body = response.into_string().unwrap();
        assert!(response_body.contains("Key successfully uploaded"));

        let pattern = format!("{}/upload/([^ \t\n]*)", BASE_URI);
        let capture_re = regex::bytes::Regex::new(&pattern).unwrap();
        let capture_content = capture_re
            .captures(response_body.as_bytes())
            .unwrap()
            .get(1)
            .unwrap()
            .as_bytes();
        String::from_utf8_lossy(capture_content).to_string()
    }

    fn vks_publish_json_get_token(client: &Client, data: &[u8]) -> String {
        let response = client
            .post("/vks/v1/upload")
            .header(ContentType::JSON)
            .body(format!(r#"{{ "keytext": "{}" }}"#, base64::encode(data)))
            .dispatch();
        let status = response.status();
        let response_body = response.into_string().unwrap();
        let result: vks_api::json::UploadResult = serde_json::from_str(&response_body).unwrap();

        assert_eq!(status, Status::Ok);
        result.token
    }

    fn vks_manage(client: &Client, search_term: &str) {
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("search_term", search_term)
            .finish();
        let response = client
            .post("/manage")
            .header(ContentType::Form)
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    fn vks_manage_delete(client: &Client, token: &str, address: &str) {
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("address", address)
            .finish();
        let response = client
            .post("/manage/unpublish")
            .header(ContentType::Form)
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }
}
