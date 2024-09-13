use std::path::{Path, PathBuf};

use crate::counters;
use handlebars::Handlebars;
use lettre::builder::{EmailBuilder, Mailbox, MimeMultipartType, PartBuilder};
use lettre::{file::FileTransport, SendmailTransport, Transport as LettreTransport};
use serde::Serialize;
use uuid::Uuid;

use gettext_macros::i18n;
use rocket_i18n::I18n;

use rfc2047::rfc2047_encode;

use crate::template_helpers;

use crate::database::types::Email;
use crate::Result;

mod context {
    #[derive(Serialize, Clone)]
    pub struct Verification {
        pub lang: String,
        pub primary_fp: String,
        pub uri: String,
        pub userid: String,
        pub base_uri: String,
        pub domain: String,
    }

    #[derive(Serialize, Clone)]
    pub struct Manage {
        pub lang: String,
        pub primary_fp: String,
        pub uri: String,
        pub base_uri: String,
        pub domain: String,
    }

    #[derive(Serialize, Clone)]
    pub struct Welcome {
        pub lang: String,
        pub primary_fp: String,
        pub uri: String,
        pub base_uri: String,
        pub domain: String,
    }
}

pub struct Service {
    from: Mailbox,
    domain: String,
    templates: Handlebars<'static>,
    transport: Transport,
}

enum Transport {
    Sendmail,
    Filemail(PathBuf),
}

impl Service {
    /// Sends mail via sendmail.
    pub fn sendmail(from: &str, base_uri: &str, template_dir: &Path) -> Result<Self> {
        Self::new(from, base_uri, template_dir, Transport::Sendmail)
    }

    /// Sends mail by storing it in the given directory.
    pub fn filemail(from: &str, base_uri: &str, template_dir: &Path, path: &Path) -> Result<Self> {
        Self::new(
            from,
            base_uri,
            template_dir,
            Transport::Filemail(path.to_owned()),
        )
    }

    fn new(from: &str, base_uri: &str, template_dir: &Path, transport: Transport) -> Result<Self> {
        let templates = template_helpers::load_handlebars(template_dir)?;
        let domain = url::Url::parse(base_uri)?
            .host_str()
            .ok_or_else(|| anyhow!("No host in base-URI"))?
            .to_string();
        Ok(Self {
            from: from.into(),
            domain,
            templates,
            transport,
        })
    }

    pub fn send_verification(
        &self,
        i18n: &I18n,
        base_uri: &str,
        tpk_name: String,
        userid: &Email,
        token: &str,
    ) -> Result<()> {
        let ctx = context::Verification {
            lang: i18n.lang.to_string(),
            primary_fp: tpk_name,
            uri: format!("{}/verify/{}", base_uri, token),
            userid: userid.to_string(),
            base_uri: base_uri.to_owned(),
            domain: self.domain.clone(),
        };

        counters::inc_mail_sent("verify", userid);

        self.send(
            &[userid],
            &i18n!(
                i18n.catalog,
                context = "Subject for verification email, {0} = userid, {1} = keyserver domain",
                "Verify {0} for your key on {1}";
                userid,
                &self.domain,
            ),
            "verify",
            i18n.lang,
            ctx,
        )
    }

    pub fn send_manage_token(
        &self,
        i18n: &I18n,
        base_uri: &str,
        tpk_name: String,
        recipient: &Email,
        link_path: &str,
    ) -> Result<()> {
        let ctx = context::Manage {
            lang: i18n.lang.to_string(),
            primary_fp: tpk_name,
            uri: format!("{}{}", base_uri, link_path),
            base_uri: base_uri.to_owned(),
            domain: self.domain.clone(),
        };

        counters::inc_mail_sent("manage", recipient);

        self.send(
            &[recipient],
            &i18n!(
                i18n.catalog,
                context = "Subject for manage email, {} = keyserver domain",
                "Manage your key on {}";
                &self.domain
            ),
            "manage",
            i18n.lang,
            ctx,
        )
    }

    pub fn send_welcome(
        &self,
        base_uri: &str,
        tpk_name: String,
        userid: &Email,
        token: &str,
    ) -> Result<()> {
        let ctx = context::Welcome {
            lang: "en".to_owned(),
            primary_fp: tpk_name,
            uri: format!("{}/upload/{}", base_uri, token),
            base_uri: base_uri.to_owned(),
            domain: self.domain.clone(),
        };

        counters::inc_mail_sent("welcome", userid);

        self.send(
            &[userid],
            &format!("Your key upload on {domain}", domain = self.domain),
            "welcome",
            "en",
            ctx,
        )
    }

    fn render_template(
        &self,
        template: &str,
        locale: &str,
        ctx: impl Serialize,
    ) -> Result<(String, String)> {
        let html = self
            .templates
            .render(&format!("{}/{}.htm", locale, template), &ctx)
            .or_else(|_| self.templates.render(&format!("{}.htm", template), &ctx))
            .map_err(|_| anyhow!("Email template failed to render"))?;
        let txt = self
            .templates
            .render(&format!("{}/{}.txt", locale, template), &ctx)
            .or_else(|_| self.templates.render(&format!("{}.txt", template), &ctx))
            .map_err(|_| anyhow!("Email template failed to render"))?;

        Ok((html, txt))
    }

    fn send(
        &self,
        to: &[&Email],
        subject: &str,
        template: &str,
        locale: &str,
        ctx: impl Serialize,
    ) -> Result<()> {
        let (html, txt) = self.render_template(template, locale, ctx)?;

        if cfg!(debug_assertions) {
            for recipient in to.iter() {
                println!("To: {}", recipient);
            }
            println!("{}", &txt);
        }

        // build this ourselves, as a temporary workaround for https://github.com/lettre/lettre/issues/400
        let text = PartBuilder::new()
            .body(txt)
            .header(("Content-Type", "text/plain; charset=utf-8"))
            .header(("Content-Transfer-Encoding", "8bit"))
            .build();

        let html = PartBuilder::new()
            .body(html)
            .header(("Content-Type", "text/html; charset=utf-8"))
            .header(("Content-Transfer-Encoding", "8bit"))
            .build();

        let email = EmailBuilder::new()
            .from(self.from.clone())
            .subject(rfc2047_encode(subject))
            .message_id(format!("<{}@{}>", Uuid::new_v4(), self.domain))
            .message_type(MimeMultipartType::Alternative)
            .header(("Content-Transfer-Encoding", "8bit"))
            .child(text)
            .child(html);

        let email = to.iter().fold(email, |email, to| email.to(to.to_string()));

        let email = email.build()?;

        match self.transport {
            Transport::Sendmail => {
                let mut transport = SendmailTransport::new();
                transport.send(email)?;
            }
            Transport::Filemail(ref path) => {
                let mut transport = FileTransport::new(path);
                transport.send(email)?;
            }
        }

        Ok(())
    }
}

// for some reason, this is no longer public in lettre itself
// FIXME replace with builtin struct on lettre update
// see https://github.com/lettre/lettre/blob/master/lettre/src/file/mod.rs#L41
#[cfg(test)]
#[derive(Deserialize)]
struct SerializableEmail {
    #[serde(alias = "envelope")]
    _envelope: lettre::Envelope,
    #[serde(alias = "message_id")]
    _message_id: String,
    message: Vec<u8>,
}

/// Returns and removes the first mail it finds from the given
/// directory.
#[cfg(test)]
pub fn pop_mail(dir: &Path) -> Result<Option<String>> {
    use std::fs;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let fh = fs::File::open(entry.path())?;
            fs::remove_file(entry.path())?;
            let mail: SerializableEmail = ::serde_json::from_reader(fh)?;
            let body = String::from_utf8_lossy(&mail.message).to_string();
            return Ok(Some(body));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod test {
    use crate::web::get_i18n;

    use super::*;
    use std::str::FromStr;
    use tempfile::{tempdir, TempDir};

    const BASEDIR: &str = "http://localhost/";
    const FROM: &str = "test@localhost";
    const TO: &str = "recipient@example.org";

    fn configure_i18n(lang: &'static str) -> I18n {
        let langs = get_i18n();
        let catalog = langs
            .clone()
            .into_iter()
            .find(|(l, _)| *l == lang)
            .unwrap()
            .1;
        rocket_i18n::I18n { catalog, lang }
    }

    fn configure_mail() -> (Service, TempDir) {
        let template_dir: PathBuf = ::std::env::current_dir()
            .unwrap()
            .join("dist/email-templates")
            .to_str()
            .unwrap()
            .into();
        let tempdir = tempdir().unwrap();
        let service = Service::filemail(FROM, BASEDIR, &template_dir, tempdir.path()).unwrap();
        (service, tempdir)
    }

    fn assert_header(headers: &[(&str, &str)], name: &str, pred: impl Fn(&str) -> bool) {
        if let Some((_, v)) = headers.iter().find(|(h, _)| *h == name) {
            assert!(pred(v));
        } else {
            panic!("Missing header: {}", name);
        }
    }

    fn check_headers(mail_content: &str) {
        // this naively assumes that all lines colons are headers, and that all headers fit in
        // a single line. that's not accurate, but ok for our testing.
        let headers: Vec<_> = mail_content
            .lines()
            .filter(|line| line.contains(": "))
            .map(|line| {
                let mut it = line.splitn(2, ": ");
                let h = it.next().unwrap();
                let v = it.next().unwrap();
                (h, v)
            })
            .collect();
        assert!(headers.contains(&("Content-Transfer-Encoding", "8bit")));
        assert!(headers.contains(&("Content-Type", "text/plain; charset=utf-8")));
        assert!(headers.contains(&("Content-Type", "text/html; charset=utf-8")));
        assert!(headers.contains(&("From", "<test@localhost>")));
        assert!(headers.contains(&("To", "<recipient@example.org>")));
        assert_header(&headers, "Content-Type", |v| {
            v.starts_with("multipart/alternative")
        });
        assert_header(&headers, "Date", |v| v.contains("+0000"));
        assert_header(&headers, "Message-ID", |v| v.contains("@localhost>"));
    }

    #[test]
    fn pop_mail_empty() {
        let (_mail, tempdir) = configure_mail();
        assert!(pop_mail(tempdir.path()).unwrap().is_none());
    }

    #[test]
    fn check_verification_mail_en() {
        let (mail, tempdir) = configure_mail();
        let i18n = configure_i18n("en");
        let recipient = Email::from_str(TO).unwrap();

        mail.send_verification(
            &i18n,
            "test",
            "fingerprintoo".to_owned(),
            &recipient,
            "token",
        )
        .unwrap();
        let mail_content = pop_mail(tempdir.path()).unwrap().unwrap();

        check_headers(&mail_content);
        assert!(mail_content.contains("lang=\"en\""));
        assert!(mail_content.contains("Hi,"));
        assert!(mail_content.contains("fingerprintoo"));
        assert!(mail_content.contains("test/verify/token"));
        assert!(mail_content.contains("test/about"));
        assert!(mail_content.contains("To let others find this key"));
    }

    #[test]
    fn check_verification_mail_ja() {
        let (mail, tempdir) = configure_mail();
        let i18n = configure_i18n("ja");
        let recipient = Email::from_str(TO).unwrap();

        mail.send_verification(
            &i18n,
            "test",
            "fingerprintoo".to_owned(),
            &recipient,
            "token",
        )
        .unwrap();
        let mail_content = pop_mail(tempdir.path()).unwrap().unwrap();

        check_headers(&mail_content);
        assert!(mail_content.contains("lang=\"ja\""));
        assert!(mail_content.contains("どうも、"));
        assert!(mail_content.contains("fingerprintoo"));
        assert!(mail_content.contains("test/verify/token"));
        assert!(mail_content.contains("test/about"));
        assert!(mail_content.contains("あなたのメールアド"));
        assert!(mail_content.contains(
            "Subject:   =?utf-8?q?localhost=E3=81=AE=E3=81=82=E3=81=AA=E3=81=9F=E3=81=AE?="
        ));
    }

    #[test]
    fn check_manage_mail_en() {
        let (mail, tempdir) = configure_mail();
        let i18n = configure_i18n("en");
        let recipient = Email::from_str(TO).unwrap();

        mail.send_manage_token(
            &i18n,
            "test",
            "fingerprintoo".to_owned(),
            &recipient,
            "token",
        )
        .unwrap();
        let mail_content = pop_mail(tempdir.path()).unwrap().unwrap();

        check_headers(&mail_content);
        assert!(mail_content.contains("lang=\"en\""));
        assert!(mail_content.contains("Hi,"));
        assert!(mail_content.contains("fingerprintoo"));
        assert!(mail_content.contains("testtoken"));
        assert!(mail_content.contains("test/about"));
        assert!(mail_content.contains("manage and delete"));
    }

    #[test]
    fn check_manage_mail_ja() {
        let (mail, tempdir) = configure_mail();
        let i18n = configure_i18n("ja");
        let recipient = Email::from_str(TO).unwrap();

        mail.send_manage_token(
            &i18n,
            "test",
            "fingerprintoo".to_owned(),
            &recipient,
            "token",
        )
        .unwrap();
        let mail_content = pop_mail(tempdir.path()).unwrap().unwrap();

        check_headers(&mail_content);
        print!("{}", mail_content);
        assert!(mail_content.contains("lang=\"ja\""));
        assert!(mail_content.contains("どうも、"));
        assert!(mail_content.contains("fingerprintoo"));
        assert!(mail_content.contains("testtoken"));
        assert!(mail_content.contains("test/about"));
        assert!(mail_content.contains("この鍵の掲示されたア"));
        assert!(mail_content.contains(
            "Subject: =?utf-8?q?localhost=E3=81=AE=E9=8D=B5=E3=82=92=E7=AE=A1=E7=90=86?="
        ));
    }

    #[test]
    fn check_welcome_mail() {
        let (mail, tempdir) = configure_mail();
        let recipient = Email::from_str(TO).unwrap();

        mail.send_welcome("test", "fingerprintoo".to_owned(), &recipient, "token")
            .unwrap();
        let mail_content = pop_mail(tempdir.path()).unwrap().unwrap();

        check_headers(&mail_content);
        assert!(mail_content.contains("lang=\"en\""));
        assert!(mail_content.contains("Hi,"));
        assert!(mail_content.contains("fingerprintoo"));
        assert!(mail_content.contains("test/upload/token"));
        assert!(mail_content.contains("test/about"));
        assert!(mail_content.contains("first time"));
    }
}
