use lazy_static::lazy_static;
use std::collections::HashSet;

use crate::database::types::Email;

// from https://github.com/mailcheck/mailcheck/wiki/List-of-Popular-Domains
lazy_static! {
    static ref POPULAR_DOMAINS: HashSet<&'static str> = vec!(
        /* Default domains included */
        "aol.com", "att.net", "comcast.net", "facebook.com", "gmail.com", "gmx.com", "googlemail.com",
        "google.com", "hotmail.com", "hotmail.co.uk", "mac.com", "me.com", "mail.com", "msn.com",
        "live.com", "sbcglobal.net", "verizon.net", "yahoo.com", "yahoo.co.uk",

        /* Other global domains */
        "email.com", "fastmail.fm", "games.com" /* AOL */, "gmx.net", "hush.com", "hushmail.com", "icloud.com",
        "iname.com", "inbox.com", "lavabit.com", "love.com" /* AOL */, "mailbox.org", "posteo.de", "outlook.com", "pobox.com", "protonmail.ch", "protonmail.com", "tutanota.de", "tutanota.com", "tutamail.com", "tuta.io",
        "keemail.me", "rocketmail.com" /* Yahoo */, "safe-mail.net", "wow.com" /* AOL */, "ygm.com" /* AOL */,
        "ymail.com" /* Yahoo */, "zoho.com", "yandex.com",

        /* United States ISP domains */
        "bellsouth.net", "charter.net", "cox.net", "earthlink.net", "juno.com",

        /* British ISP domains */
        "btinternet.com", "virginmedia.com", "blueyonder.co.uk", "freeserve.co.uk", "live.co.uk",
        "ntlworld.com", "o2.co.uk", "orange.net", "sky.com", "talktalk.co.uk", "tiscali.co.uk",
        "virgin.net", "wanadoo.co.uk", "bt.com",

        /* Domains used in Asia */
        "sina.com", "sina.cn", "qq.com", "naver.com", "hanmail.net", "daum.net", "nate.com", "yahoo.co.jp", "yahoo.co.kr", "yahoo.co.id", "yahoo.co.in", "yahoo.com.sg", "yahoo.com.ph", "163.com", "yeah.net", "126.com", "21cn.com", "aliyun.com", "foxmail.com",

        /* French ISP domains */
        "hotmail.fr", "live.fr", "laposte.net", "yahoo.fr", "wanadoo.fr", "orange.fr", "gmx.fr", "sfr.fr", "neuf.fr", "free.fr",

        /* German ISP domains */
        "gmx.de", "hotmail.de", "live.de", "online.de", "t-online.de" /* T-Mobile */, "web.de", "yahoo.de",

        /* Italian ISP domains */
        "libero.it", "virgilio.it", "hotmail.it", "aol.it", "tiscali.it", "alice.it", "live.it", "yahoo.it", "email.it", "tin.it", "poste.it", "teletu.it",

        /* Russian ISP domains */
        "mail.ru", "rambler.ru", "yandex.ru", "ya.ru", "list.ru",

        /* Belgian ISP domains */
        "hotmail.be", "live.be", "skynet.be", "voo.be", "tvcablenet.be", "telenet.be",

        /* Argentinian ISP domains */
        "hotmail.com.ar", "live.com.ar", "yahoo.com.ar", "fibertel.com.ar", "speedy.com.ar", "arnet.com.ar",

        /* Domains used in Mexico */
        "yahoo.com.mx", "live.com.mx", "hotmail.es", "hotmail.com.mx", "prodigy.net.mx",

        /* Domains used in Brazil */
        "yahoo.com.br", "hotmail.com.br", "outlook.com.br", "uol.com.br", "bol.com.br", "terra.com.br", "ig.com.br", "itelefonica.com.br", "r7.com", "zipmail.com.br", "globo.com", "globomail.com", "oi.com.br"
    ).into_iter().collect();
}

pub fn anonymize_address(email: &Email) -> Option<String> {
    email
        .as_str()
        .rsplit('@')
        .next()
        .map(|domain| domain.to_lowercase())
        .and_then(|domain| {
            if POPULAR_DOMAINS.contains(&domain.as_str()) {
                Some(domain)
            } else {
                domain.rsplit('.').next().map(|tld| tld.to_owned())
            }
        })
}

pub fn anonymize_address_fallback(email: &Email) -> String {
    anonymize_address(email).unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn known_domain() {
        let email = "user@hotmail.be".parse::<Email>().unwrap();
        assert_eq!("hotmail.be", anonymize_address(&email).unwrap());
    }

    #[test]
    fn unknown_domain() {
        let email = "user@example.org".parse::<Email>().unwrap();
        assert_eq!("org", anonymize_address(&email).unwrap());
    }
}
