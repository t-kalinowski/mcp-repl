use std::sync::OnceLock;

use htmd::HtmlToMarkdown;

fn converter() -> &'static HtmlToMarkdown {
    static CONVERTER: OnceLock<HtmlToMarkdown> = OnceLock::new();
    CONVERTER.get_or_init(|| {
        HtmlToMarkdown::builder()
            .skip_tags(vec!["head", "script", "style", "nav", "noscript"])
            .build()
    })
}

pub fn convert(html: &str) -> std::io::Result<String> {
    converter().convert(html)
}
