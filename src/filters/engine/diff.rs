use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiffEvent {
    Insert {
        path: DiffPath,
        node: DiffNode,
        source: DiffSource,
    },
    Delete {
        path: DiffPath,
        old: DiffNode,
        source: DiffSource,
    },
    Replace {
        path: DiffPath,
        old: DiffNode,
        new: DiffNode,
        source: DiffSource,
    },
    Move {
        from: DiffPath,
        to: DiffPath,
        node: DiffNode,
        source: DiffSource,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiffSource {
    HttpMeta,
    Header,
    Cookie,
    Url,
    Body(BodyDiffSource),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyDiffSource {
    Text,
    Json,
    Xml,
    Html,
    JavaScript,
    Css,
    Ast {
        language: String,
    },
    Binary,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DiffPath {
    pub segments: Vec<DiffPathSegment>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum DiffPathSegment {
    Method,
    Scheme,
    Host,
    Path,
    Query,
    QueryParam(String),
    Header(String),
    Cookie(String),
    SetCookie(String),
    Status,
    Body,
    JsonKey(String),
    JsonIndex(usize),
    XmlElement(String),
    XmlAttribute(String),
    XmlText,
    HtmlElement {
        tag: String,
        ordinal: usize,
    },
    HtmlAttribute(String),
    HtmlText,
    AstNode {
        kind: String,
        ordinal: usize,
    },
    AstField {
        name: String,
    },
    TextRange {
        start: usize,
        end: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiffNode {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Text(String),
    BytesLen(usize),
    Header {
        name: String,
        value: String,
    },
    Cookie {
        name: String,
        value: String,
    },
    Json {
        raw: String,
    },
    Xml {
        name: Option<String>,
        text: String,
    },
    Html {
        tag: Option<String>,
        text: String,
    },
    Ast {
        kind: String,
        text: String,
    },
    Binary {
        bytes_len: usize,
        content_type: Option<String>,
    },
}

impl DiffEvent {
    pub fn path(&self) -> &DiffPath {
        match self {
            Self::Insert { path, .. }
            | Self::Delete { path, .. }
            | Self::Replace { path, .. } => path,
            Self::Move { to, .. } => to,
        }
    }

    pub fn source(&self) -> DiffSource {
        match self {
            Self::Insert { source, .. }
            | Self::Delete { source, .. }
            | Self::Replace { source, .. }
            | Self::Move { source, .. } => source.clone(),
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Insert { path, node, .. } => {
                format!("insert {} = {}", path, node.summary())
            }
            Self::Delete { path, old, .. } => {
                format!("delete {} = {}", path, old.summary())
            }
            Self::Replace { path, old, new, .. } => {
                format!("replace {}: {} -> {}", path, old.summary(), new.summary())
            }
            Self::Move { from, to, node, .. } => {
                format!("move {} -> {} = {}", from, to, node.summary())
            }
        }
    }
}

impl DiffPath {
    pub fn new(segments: Vec<DiffPathSegment>) -> Self {
        Self { segments }
    }

    pub fn method() -> Self {
        Self::new(vec![DiffPathSegment::Method])
    }

    pub fn scheme() -> Self {
        Self::new(vec![DiffPathSegment::Scheme])
    }

    pub fn host() -> Self {
        Self::new(vec![DiffPathSegment::Host])
    }

    pub fn path() -> Self {
        Self::new(vec![DiffPathSegment::Path])
    }

    pub fn query() -> Self {
        Self::new(vec![DiffPathSegment::Query])
    }

    pub fn status() -> Self {
        Self::new(vec![DiffPathSegment::Status])
    }

    pub fn header(name: impl Into<String>) -> Self {
        Self::new(vec![DiffPathSegment::Header(name.into())])
    }

    pub fn body() -> Self {
        Self::new(vec![DiffPathSegment::Body])
    }

    pub fn body_json(segments: Vec<DiffPathSegment>) -> Self {
        let mut all = vec![DiffPathSegment::Body];
        all.extend(segments);
        Self::new(all)
    }

    pub fn body_json_key_path(keys: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::body_json(
            keys.into_iter()
                .map(|key| DiffPathSegment::JsonKey(key.into()))
                .collect(),
        )
    }
}

impl DiffNode {
    pub fn summary(&self) -> String {
        match self {
            Self::Null => "null".to_string(),
            Self::Bool(value) => value.to_string(),
            Self::Number(value) => value.clone(),
            Self::String(value) => quoted_short(value),
            Self::Text(value) => quoted_short(value),
            Self::BytesLen(len) => format!("{len} bytes"),
            Self::Header { name, value } => format!("{name}: {}", quoted_short(value)),
            Self::Cookie { name, value } => format!("{name}={}", quoted_short(value)),
            Self::Json { raw } => format!("json {}", quoted_short(raw)),
            Self::Xml { name, text } => {
                if let Some(name) = name {
                    format!("xml <{name}> {}", quoted_short(text))
                } else {
                    format!("xml {}", quoted_short(text))
                }
            }
            Self::Html { tag, text } => {
                if let Some(tag) = tag {
                    format!("html <{tag}> {}", quoted_short(text))
                } else {
                    format!("html {}", quoted_short(text))
                }
            }
            Self::Ast { kind, text } => {
                format!("ast {kind} {}", quoted_short(text))
            }
            Self::Binary {
                bytes_len,
                content_type,
            } => {
                if let Some(content_type) = content_type {
                    format!("binary {bytes_len} bytes, {content_type}")
                } else {
                    format!("binary {bytes_len} bytes")
                }
            }
        }
    }
}

impl fmt::Display for DiffPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.segments.is_empty() {
            return f.write_str("/");
        }

        for segment in &self.segments {
            f.write_str("/")?;
            match segment {
                DiffPathSegment::Method => f.write_str("method")?,
                DiffPathSegment::Scheme => f.write_str("scheme")?,
                DiffPathSegment::Host => f.write_str("host")?,
                DiffPathSegment::Path => f.write_str("path")?,
                DiffPathSegment::Query => f.write_str("query")?,
                DiffPathSegment::QueryParam(name) => {
                    write!(f, "query/{}", escape_path_segment(name))?
                }
                DiffPathSegment::Status => f.write_str("status")?,
                DiffPathSegment::Header(name) => {
                    write!(f, "headers/{}", escape_path_segment(name))?
                }
                DiffPathSegment::Cookie(name) => {
                    write!(f, "cookies/{}", escape_path_segment(name))?
                }
                DiffPathSegment::SetCookie(name) => {
                    write!(f, "set-cookie/{}", escape_path_segment(name))?
                }
                DiffPathSegment::Body => f.write_str("body")?,
                DiffPathSegment::JsonKey(key) => {
                    write!(f, "{}", escape_path_segment(key))?
                }
                DiffPathSegment::JsonIndex(index) => write!(f, "{index}")?,
                DiffPathSegment::XmlElement(name) => {
                    write!(f, "xml/{}", escape_path_segment(name))?
                }
                DiffPathSegment::XmlAttribute(name) => {
                    write!(f, "xml/@{}", escape_path_segment(name))?
                }
                DiffPathSegment::XmlText => f.write_str("xml/text")?,
                DiffPathSegment::HtmlElement { tag, ordinal } => {
                    write!(f, "html/{}#{ordinal}", escape_path_segment(tag))?
                }
                DiffPathSegment::HtmlAttribute(name) => {
                    write!(f, "html/@{}", escape_path_segment(name))?
                }
                DiffPathSegment::HtmlText => f.write_str("html/text")?,
                DiffPathSegment::AstNode { kind, ordinal } => {
                    write!(f, "ast/{}#{ordinal}", escape_path_segment(kind))?
                }
                DiffPathSegment::AstField { name } => {
                    write!(f, "field/{}", escape_path_segment(name))?
                }
                DiffPathSegment::TextRange { start, end } => {
                    write!(f, "text-range/{start}-{end}")?
                }
            }
        }

        Ok(())
    }
}

fn escape_path_segment(value: &str) -> String {
    value
        .replace('~', "~0")
        .replace('/', "~1")
}

fn quoted_short(value: &str) -> String {
    const MAX: usize = 80;

    let mut out = value.chars().take(MAX).collect::<String>();

    if value.chars().count() > MAX {
        out.push('…');
    }

    format!("{out:?}")
}

pub struct JsonBodyDiffEngine;
pub struct XmlBodyDiffEngine;
pub struct HtmlBodyDiffEngine;
pub struct JavaScriptBodyDiffEngine;
pub struct CssBodyDiffEngine;
pub struct TextBodyDiffEngine;

#[allow(unused)]
pub struct BodyDiffDispatcher {
    engines: Vec<Box<dyn BodyDiffEngine>>,
}

pub trait BodyDiffEngine {
    fn supports(&self, content_type: Option<&str>, text: &str) -> bool;

    fn diff(
        &self,
        original: &str,
        edited: &str,
        content_type: Option<&str>,
    ) -> Option<DiffEvent>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodySyntax {
    Json,
    Xml,
    Html,
    JavaScript,
    Css,
    Text,
    Binary,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffConfidence {
    Low,
    Medium,
    High,
}

pub enum BodyDiffFallbackReason {
    UnsupportedContentType,
    ParseFailed(String),
    TooLarge,
    BinaryBody,
    NoStableAnchor,
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_header_path() {
        let path = DiffPath::header("content-type");

        assert_eq!(path.to_string(), "/headers/content-type");
    }

    #[test]
    fn formats_json_body_path() {
        let path = DiffPath::body_json(vec![
            DiffPathSegment::JsonKey("user".to_string()),
            DiffPathSegment::JsonKey("name".to_string()),
        ]);

        assert_eq!(path.to_string(), "/body/user/name");
    }

    #[test]
    fn summarizes_replace_event() {
        let event = DiffEvent::Replace {
            path: DiffPath::status(),
            old: DiffNode::Number("404".to_string()),
            new: DiffNode::Number("200".to_string()),
            source: DiffSource::HttpMeta,
        };

        assert_eq!(event.summary(), "replace /status: 404 -> 200");
    }
}

