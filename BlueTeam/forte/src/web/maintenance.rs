use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Method;
use rocket::{Data, Request};
use rocket_dyn_templates::Template;
use rocket_i18n::I18n;
use serde_json::json;

use std::fs;
use std::path::PathBuf;

use crate::web::MyResponse;

pub struct MaintenanceMode {
    maintenance_file: PathBuf,
}

mod templates {
    #[derive(Serialize)]
    pub struct MaintenanceMode {
        pub message: String,
        pub commit: String,
        pub version: String,
        pub lang: String,
    }
}

#[async_trait]
impl Fairing for MaintenanceMode {
    fn info(&self) -> Info {
        Info {
            name: "Maintenance Mode",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        let message = match self.get_maintenance_message() {
            Some(message) => message,
            None => return,
        };

        let path = request.uri().path().as_str();
        if self.is_request_json(path) {
            request.set_uri(uri!(maintenance_error_json(message)));
            request.set_method(Method::Get);
        } else if self.is_request_plain(path, request.method()) {
            request.set_uri(uri!(maintenance_error_plain(message)));
            request.set_method(Method::Get);
        } else if self.is_request_web(path) {
            request.set_uri(uri!(maintenance_error_web(message)));
            request.set_method(Method::Get);
        }
    }
}

impl MaintenanceMode {
    pub fn new(maintenance_file: PathBuf) -> Self {
        MaintenanceMode { maintenance_file }
    }

    fn is_request_json(&self, path: &str) -> bool {
        path.starts_with("/vks/v1/upload") || path.starts_with("/vks/v1/request-verify")
    }

    fn is_request_plain(&self, path: &str, method: Method) -> bool {
        path.starts_with("/pks/add") || method == Method::Put
    }

    fn is_request_web(&self, path: &str) -> bool {
        path.starts_with("/upload") || path.starts_with("/manage") || path.starts_with("/verify")
    }

    fn get_maintenance_message(&self) -> Option<String> {
        if !self.maintenance_file.exists() {
            return None;
        }
        fs::read_to_string(&self.maintenance_file).ok()
    }
}

#[get("/maintenance/plain/<message>")]
pub fn maintenance_error_plain(message: String) -> MyResponse {
    MyResponse::MaintenancePlain(message)
}

#[derive(Serialize)]
struct JsonErrorMessage {
    message: String,
}

#[get("/maintenance/json/<message>")]
pub fn maintenance_error_json(message: String) -> MyResponse {
    MyResponse::MaintenanceJson(json!(JsonErrorMessage { message }))
}

#[get("/maintenance/web/<message>")]
pub fn maintenance_error_web(message: String, i18n: I18n) -> MyResponse {
    let ctx = templates::MaintenanceMode {
        message,
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
        lang: i18n.lang.to_owned(),
    };
    MyResponse::Maintenance(Template::render("maintenance", ctx))
}
