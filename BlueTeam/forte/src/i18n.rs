use handlebars::{
    Context, Handlebars, Helper, HelperDef, HelperResult, Output, RenderContext, RenderError,
};

use std::io;

pub struct I18NHelper {
    catalogs: Vec<(&'static str, gettext::Catalog)>,
}

impl I18NHelper {
    pub fn new(catalogs: Vec<(&'static str, gettext::Catalog)>) -> Self {
        Self { catalogs }
    }

    pub fn get_catalog(&self, lang: &str) -> &gettext::Catalog {
        let (_, ref catalog) = self
            .catalogs
            .iter()
            .find(|(candidate, _)| *candidate == lang)
            .unwrap_or_else(|| self.catalogs.get(0).unwrap());
        catalog
    }

    // Traverse the fallback chain,
    pub fn lookup<'a>(
        &'a self,
        lang: &str,
        text_id: &'a str,
        // args: Option<&HashMap<&str, FluentValue>>,
    ) -> &'a str {
        let catalog = self.get_catalog(lang);
        catalog.gettext(text_id)
        // format!("Unknown localization {}", text_id)
    }
}

#[derive(Default)]
struct StringOutput {
    pub s: String,
}

impl Output for StringOutput {
    fn write(&mut self, seg: &str) -> Result<(), io::Error> {
        self.s.push_str(seg);
        Ok(())
    }
}

impl HelperDef for I18NHelper {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'reg, 'rc>,
        reg: &'reg Handlebars,
        context: &'rc Context,
        rcx: &mut RenderContext<'reg, '_>,
        out: &mut dyn Output,
    ) -> HelperResult {
        let id = if let Some(id) = h.param(0) {
            id
        } else {
            return Err(RenderError::new(
                "{{text}} must have at least one parameter",
            ));
        };

        let id = if let Some(id) = id.value().as_str() {
            id
        } else {
            return Err(RenderError::new("{{text}} takes an identifier parameter"));
        };

        let rerender = h
            .param(1)
            .and_then(|p| p.relative_path().map(|v| v == "rerender"))
            .unwrap_or(false);

        let lang = context
            .data()
            .get("lang")
            .expect("Language not set in context")
            .as_str()
            .expect("Language must be string");

        fn render_error_with<E>(e: E) -> RenderError
        where
            E: std::error::Error + Send + Sync + 'static,
        {
            RenderError::from_error("Failed to render", e)
        }
        let response = self.lookup(lang, id);
        if rerender {
            let data = rcx.evaluate(context, "this").unwrap();
            let response = reg
                .render_template(response, data.as_json())
                .map_err(render_error_with)?;
            out.write(&response).map_err(render_error_with)?;
        } else {
            out.write(response).map_err(render_error_with)?;
        }
        Ok(())
    }
}
