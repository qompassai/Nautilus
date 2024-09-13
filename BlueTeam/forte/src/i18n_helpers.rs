use crate::database::Query;
use gettext_macros::i18n;
use rocket_i18n::I18n;

pub fn describe_query_error(i18n: &I18n, q: &Query) -> String {
    match q {
        Query::ByFingerprint(fpr) => {
            i18n!(i18n.catalog, "No key found for fingerprint {}"; fpr)
        }
        Query::ByKeyID(key_id) => {
            i18n!(i18n.catalog, "No key found for key id {}"; key_id)
        }
        Query::ByEmail(email) => {
            i18n!(i18n.catalog, "No key found for email address {}"; email)
        }
        Query::InvalidShort() => {
            i18n!(i18n.catalog, "Search by Short Key ID is not supported.")
        }
        Query::Invalid() => i18n!(i18n.catalog, "Invalid search query."),
    }
}
