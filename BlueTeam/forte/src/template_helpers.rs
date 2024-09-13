use std::collections::HashSet;
use std::path::{Path, PathBuf};

use handlebars::Handlebars;

use crate::i18n::I18NHelper;
use crate::web::get_i18n;
use crate::Result;

#[derive(Debug)]
pub struct TemplateOverrides(String, HashSet<String>);

impl TemplateOverrides {
    pub fn load(template_path: &Path, localized_dir: &str) -> Result<Self> {
        load_localized_template_names(template_path, localized_dir)
            .map(|vec| Self(localized_dir.to_owned(), vec))
    }

    pub fn get_template_override(&self, lang: &str, tmpl: &str) -> Option<String> {
        let template_name = format!("{}/{}/{}", self.0, lang, tmpl);
        if self.1.contains(&template_name) {
            println!("{}", &template_name);
            Some(template_name)
        } else {
            None
        }
    }
}

fn load_localized_template_names(
    template_path: &Path,
    localized_dir: &str,
) -> Result<HashSet<String>> {
    let language_glob = template_path.join(localized_dir).join("*");
    glob::glob(language_glob.to_str().expect("valid glob path string"))
        .unwrap()
        .flatten()
        .flat_map(|language_path| {
            let mut template_glob = language_path.join("**").join("*");
            template_glob.set_extension("hbs");
            glob::glob(template_glob.to_str().expect("valid glob path string"))
                .unwrap()
                .flatten()
                .map(move |path| {
                    // TODO this is a hack
                    let template_name =
                        remove_extension(remove_extension(path.strip_prefix(&template_path)?));
                    Ok(template_name.to_string_lossy().into_owned())
                })
        })
        .collect()
}

pub fn load_handlebars(template_dir: &Path) -> Result<Handlebars<'static>> {
    let mut handlebars = Handlebars::new();

    let i18ns = get_i18n();
    let i18n_helper = I18NHelper::new(i18ns);
    handlebars.register_helper("text", Box::new(i18n_helper));

    let mut glob_path = template_dir.join("**").join("*");
    glob_path.set_extension("hbs");
    let glob_path = glob_path.to_str().expect("valid glob path string");

    for path in glob::glob(glob_path).unwrap().flatten() {
        let template_name = remove_extension(path.strip_prefix(template_dir)?);
        handlebars.register_template_file(&template_name.to_string_lossy(), &path)?;
    }

    Ok(handlebars)
}

fn remove_extension<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();
    let stem = match path.file_stem() {
        Some(stem) => stem,
        None => return path.to_path_buf(),
    };

    match path.parent() {
        Some(parent) => parent.join(stem),
        None => PathBuf::from(stem),
    }
}
