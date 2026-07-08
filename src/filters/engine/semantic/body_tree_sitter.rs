use crate::filters::GeneratedJsonPatchOperation;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyDiffKind {
    Json,
    Html,
    Xml,
    Text,
    Ast {
        language: BodyLanguage,
    },
    Binary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyLanguage {
    Json,
    Html,
    Xml,
    JavaScript,
    Css,
    PlainText,
}

impl BodyLanguage {
    pub fn from_content_type(content_type: Option<&str>) -> Self {
        let Some(content_type) = content_type else {
            return Self::PlainText;
        };

        let content_type = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim()
            .to_ascii_lowercase();

        match content_type.as_str() {
            "application/json" | "text/json" => Self::Json,
            "text/html" | "application/xhtml+xml" => Self::Html,
            "application/xml" | "text/xml" => Self::Xml,
            "application/javascript"
            | "text/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "text/ecmascript" => Self::JavaScript,
            "text/css" => Self::Css,
            _ if content_type.ends_with("+json") => Self::Json,
            _ if content_type.ends_with("+xml") => Self::Xml,
            _ => Self::PlainText,
        }
    }

    pub fn is_ast_like(&self) -> bool {
        matches!(self, Self::Html | Self::JavaScript | Self::Css)
    }

    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Html => "HTML",
            Self::Xml => "XML",
            Self::JavaScript => "JavaScript",
            Self::Css => "CSS",
            Self::PlainText => "PlainText",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AstPathSegment {
    pub kind: String,
    pub field_name: Option<String>,
    pub name: Option<String>,
    pub ordinal: usize,
    pub text_fragment: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RewriteConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyRewriteIntent {
    pub language: BodyLanguage,
    pub anchor: BodyAnchor,
    pub operation: BodyRewriteOperation,
    pub confidence: RewriteConfidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyAnchor {
    ContainsText(String),
    ContainsAll(Vec<String>),
    AstNode {
        kind: String,
        text_fragment: String,
    },
    AstPath {
        segments: Vec<AstPathSegment>,
    },
    TextRange {
        before: String,
        after: String,
    },
    JsProperty {
        property: String,
    },
    CssDeclaration {
        property: String,
    },
    HtmlAttribute {
        element: Option<String>,
        attribute: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyRewriteOperation {
    ReplaceWholeBody {
        edited_body: String,
        content_type: String,
    },
    ReplaceText {
        old: String,
        new: String,
    },
    ReplaceTextOnce {
        old: String,
        new: String,
    },
    ReplaceTextAll {
        old: String,
        new: String,
    },
    ReplaceRegex {
        pattern: String,
        replacement: String,
    },
    ReplaceTextWhenContains {
        anchor: String,
        old: String,
        new: String,
    },
    ReplaceJsProperty {
        property: String,
        old: String,
        new: String,
    },
    ReplaceCssDeclaration {
        property: String,
        old: String,
        new: String,
    },
    ReplaceHtmlAttribute {
        selector: String,
        attribute: String,
        old: String,
        new: String,
    },
    InsertText {
        anchor: String,
        text: String,
    },
    DeleteText {
        text: String,
    },
    JsonPatch {
        operations: Vec<GeneratedJsonPatchOperation>,
        resulting_body: String,
        content_type: String,
    },
}

pub enum RewriteOp {
    Add {
        target: RewriteTarget,
        value: String,
    },
    Remove {
        target: RewriteTarget,
    },
    Replace {
        target: RewriteTarget,
        old: Option<String>,
        new: String,
    },
    Move {
        from: RewriteTarget,
        to: RewriteTarget,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeSitterAnchor {
    pub language: BodyLanguage,
    pub anchor: BodyAnchor,
    pub operation: BodyRewriteOperation,
    pub ast_path: Vec<AstPathSegment>,
    pub changed_node_kind: String,
    pub changed_text: String,
    pub confidence: RewriteConfidence,
}

pub fn extract_body_rewrite_intent(
    original: &str,
    edited: &str,
    content_type: Option<&str>,
) -> Option<BodyRewriteIntent> {
    if original == edited {
        return None;
    }

    let language = BodyLanguage::from_content_type(content_type);

    if language.is_ast_like()
        && let Some(anchor) = extract_tree_sitter_anchor(language.clone(), original, edited)
    {
        return Some(BodyRewriteIntent {
            language: anchor.language,
            anchor: anchor.anchor,
            operation: anchor.operation,
            confidence: anchor.confidence,
        });
    }

    extract_text_rewrite_intent(language, original, edited)
}

pub fn extract_tree_sitter_anchor(
    language: BodyLanguage,
    original: &str,
    edited: &str,
) -> Option<TreeSitterAnchor> {
    let replacement = single_text_replacement(original, edited)?;

    match language {
        BodyLanguage::JavaScript => extract_javascript_tree_sitter_anchor(original, &replacement),
        BodyLanguage::Css => extract_css_tree_sitter_anchor(original, &replacement),
        BodyLanguage::Html => extract_html_tree_sitter_anchor(original, &replacement),
        BodyLanguage::Json | BodyLanguage::Xml | BodyLanguage::PlainText => None,
    }
}

fn extract_javascript_tree_sitter_anchor(
    original: &str,
    replacement: &TextReplacement,
) -> Option<TreeSitterAnchor> {
    let tree = parse_tree(BodyLanguage::JavaScript, original)?;
    let changed_node = smallest_node_covering_range(tree.root_node(), replacement.start, replacement.end)?;
    let ast_path = ast_path_for_node(changed_node, original.as_bytes());

    if let Some(property) = javascript_property_anchor(changed_node, original.as_bytes()) {
        let anchor = BodyAnchor::JsProperty {
            property: property.clone(),
        };
        let replacement = expand_replacement_to_ancestor_kinds(
            changed_node,
            original,
            replacement,
            &["string"],
        )
            .unwrap_or_else(|| replacement.clone());

        return Some(TreeSitterAnchor {
            language: BodyLanguage::JavaScript,
            anchor,
            operation: BodyRewriteOperation::ReplaceJsProperty {
                property,
                old: replacement.old.clone(),
                new: replacement.new.clone(),
            },
            ast_path,
            changed_node_kind: changed_node.kind().to_string(),
            changed_text: replacement.old.clone(),
            confidence: RewriteConfidence::High,
        });
    }

    let anchor_text = node_text_fragment(changed_node, original.as_bytes())
        .unwrap_or_else(|| replacement.old.clone());

    Some(TreeSitterAnchor {
        language: BodyLanguage::JavaScript,
        anchor: BodyAnchor::AstNode {
            kind: changed_node.kind().to_string(),
            text_fragment: anchor_text,
        },
        operation: BodyRewriteOperation::ReplaceTextOnce {
            old: replacement.old.clone(),
            new: replacement.new.clone(),
        },
        ast_path,
        changed_node_kind: changed_node.kind().to_string(),
        changed_text: replacement.old.clone(),
        confidence: RewriteConfidence::Medium,
    })
}

fn expand_replacement_to_ancestor_kinds(
    mut node: tree_sitter::Node<'_>,
    original: &str,
    replacement: &TextReplacement,
    ancestor_kinds: &[&str],
) -> Option<TextReplacement> {
    loop {
        if ancestor_kinds.contains(&node.kind()) {
            let start = node.start_byte();
            let end = node.end_byte();

            if start > replacement.start || end < replacement.end {
                return None;
            }

            let old = original.get(start..end)?.to_string();
            let new = old.replacen(&replacement.old, &replacement.new, 1);

            if old == new {
                return None;
            }

            return Some(TextReplacement {
                start,
                end,
                old,
                new,
            });
        }

        node = node.parent()?;
    }
}

fn extract_css_tree_sitter_anchor(
    original: &str,
    replacement: &TextReplacement,
) -> Option<TreeSitterAnchor> {
    let tree = parse_tree(BodyLanguage::Css, original)?;
    let changed_node = smallest_node_covering_range(tree.root_node(), replacement.start, replacement.end)?;
    let ast_path = ast_path_for_node(changed_node, original.as_bytes());

    if let Some(property) = css_declaration_property_anchor(changed_node, original.as_bytes()) {
        return Some(TreeSitterAnchor {
            language: BodyLanguage::Css,
            anchor: BodyAnchor::CssDeclaration {
                property: property.clone(),
            },
            operation: BodyRewriteOperation::ReplaceCssDeclaration {
                property,
                old: replacement.old.clone(),
                new: replacement.new.clone(),
            },
            ast_path,
            changed_node_kind: changed_node.kind().to_string(),
            changed_text: replacement.old.clone(),
            confidence: RewriteConfidence::High,
        });
    }

    let anchor_text = node_text_fragment(changed_node, original.as_bytes())
        .unwrap_or_else(|| replacement.old.clone());

    Some(TreeSitterAnchor {
        language: BodyLanguage::Css,
        anchor: BodyAnchor::AstNode {
            kind: changed_node.kind().to_string(),
            text_fragment: anchor_text,
        },
        operation: BodyRewriteOperation::ReplaceTextOnce {
            old: replacement.old.clone(),
            new: replacement.new.clone(),
        },
        ast_path,
        changed_node_kind: changed_node.kind().to_string(),
        changed_text: replacement.old.clone(),
        confidence: RewriteConfidence::Medium,
    })
}

fn extract_html_tree_sitter_anchor(
    original: &str,
    replacement: &TextReplacement,
) -> Option<TreeSitterAnchor> {
    let tree = parse_tree(BodyLanguage::Html, original)?;
    let changed_node = smallest_node_covering_range(tree.root_node(), replacement.start, replacement.end)?;
    let ast_path = ast_path_for_node(changed_node, original.as_bytes());

    if let Some((element, attribute)) = html_attribute_anchor(changed_node, original.as_bytes()) {
        let selector = element.clone().unwrap_or_else(|| "*".to_string());

        return Some(TreeSitterAnchor {
            language: BodyLanguage::Html,
            anchor: BodyAnchor::HtmlAttribute {
                element,
                attribute: attribute.clone(),
            },
            operation: BodyRewriteOperation::ReplaceHtmlAttribute {
                selector,
                attribute,
                old: replacement.old.clone(),
                new: replacement.new.clone(),
            },
            ast_path,
            changed_node_kind: changed_node.kind().to_string(),
            changed_text: replacement.old.clone(),
            confidence: RewriteConfidence::High,
        });
    }

    let anchor_text = node_text_fragment(changed_node, original.as_bytes())
        .unwrap_or_else(|| replacement.old.clone());

    Some(TreeSitterAnchor {
        language: BodyLanguage::Html,
        anchor: BodyAnchor::AstNode {
            kind: changed_node.kind().to_string(),
            text_fragment: anchor_text,
        },
        operation: BodyRewriteOperation::ReplaceTextOnce {
            old: replacement.old.clone(),
            new: replacement.new.clone(),
        },
        ast_path,
        changed_node_kind: changed_node.kind().to_string(),
        changed_text: replacement.old.clone(),
        confidence: RewriteConfidence::Medium,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TextReplacement {
    start: usize,
    end: usize,
    old: String,
    new: String,
}

fn extract_text_rewrite_intent(
    language: BodyLanguage,
    original: &str,
    edited: &str,
) -> Option<BodyRewriteIntent> {
    let Some(replacement) = single_text_replacement(original, edited) else {
        return Some(BodyRewriteIntent {
            language,
            anchor: BodyAnchor::ContainsText(stable_text_anchor(original)?),
            operation: BodyRewriteOperation::ReplaceWholeBody {
                edited_body: edited.to_string(),
                content_type: "text/plain; charset=utf-8".to_string(),
            },
            confidence: RewriteConfidence::Low,
        });
    };

    Some(BodyRewriteIntent {
        language,
        anchor: BodyAnchor::ContainsText(replacement.old.clone()),
        operation: BodyRewriteOperation::ReplaceTextOnce {
            old: replacement.old,
            new: replacement.new,
        },
        confidence: RewriteConfidence::Medium,
    })
}

fn single_text_replacement(original: &str, edited: &str) -> Option<TextReplacement> {
    let start = common_prefix_len(original, edited);
    let suffix_len = common_suffix_len(&original[start..], &edited[start..]);

    let original_end = original.len().checked_sub(suffix_len)?;
    let edited_end = edited.len().checked_sub(suffix_len)?;

    if start > original_end || start > edited_end {
        return None;
    }

    let old = &original[start..original_end];
    let new = &edited[start..edited_end];

    if old.is_empty() && new.is_empty() {
        return None;
    }

    if old.len() > 4096 || new.len() > 4096 {
        return None;
    }

    Some(TextReplacement {
        start,
        end: original_end,
        old: old.to_string(),
        new: new.to_string(),
    })
}

fn common_prefix_len(left: &str, right: &str) -> usize {
    left.char_indices()
        .zip(right.char_indices())
        .take_while(|((_, left), (_, right))| left == right)
        .map(|((idx, ch), _)| idx + ch.len_utf8())
        .last()
        .unwrap_or(0)
}

fn common_suffix_len(left: &str, right: &str) -> usize {
    left.char_indices()
        .rev()
        .zip(right.char_indices().rev())
        .take_while(|((_, left), (_, right))| left == right)
        .map(|((idx, _), _)| left.len() - idx)
        .last()
        .unwrap_or(0)
}

fn stable_text_anchor(text: &str) -> Option<String> {
    const MIN_ANCHOR_CHARS: usize = 8;
    const MAX_ANCHOR_CHARS: usize = 96;

    for line in text.lines().map(str::trim) {
        if line.chars().count() >= MIN_ANCHOR_CHARS {
            return Some(line.chars().take(MAX_ANCHOR_CHARS).collect());
        }
    }

    let anchor = text
        .trim()
        .chars()
        .take(MAX_ANCHOR_CHARS)
        .collect::<String>();

    if anchor.chars().count() >= MIN_ANCHOR_CHARS {
        Some(anchor)
    } else {
        None
    }
}

fn parse_tree(language: BodyLanguage, source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();

    match language {
        BodyLanguage::JavaScript => parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .ok()?,
        BodyLanguage::Css => parser
            .set_language(&tree_sitter_css::LANGUAGE.into())
            .ok()?,
        BodyLanguage::Html => parser
            .set_language(&tree_sitter_html::LANGUAGE.into())
            .ok()?,
        BodyLanguage::Json | BodyLanguage::Xml | BodyLanguage::PlainText => return None,
    }

    parser.parse(source, None)
}

fn smallest_node_covering_range(
    node: tree_sitter::Node<'_>,
    start: usize,
    end: usize,
) -> Option<tree_sitter::Node<'_>> {
    if start < node.start_byte() || end > node.end_byte() {
        return None;
    }

    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if start >= child.start_byte()
            && end <= child.end_byte()
            && let Some(found) = smallest_node_covering_range(child, start, end)
        {
            return Some(found);
        }
    }

    Some(node)
}

fn ast_path_for_node(
    mut node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Vec<AstPathSegment> {
    let mut out = Vec::new();

    loop {
        let ordinal = sibling_ordinal(node);
        let text_fragment = node_text_fragment(node, source);

        out.push(AstPathSegment {
            kind: node.kind().to_string(),
            field_name: field_name_for_node(node),
            name: semantic_node_name(node, source),
            ordinal,
            text_fragment,
        });

        let Some(parent) = node.parent() else {
            break;
        };

        node = parent;
    }

    out.reverse();
    out
}

fn field_name_for_node(node: tree_sitter::Node<'_>) -> Option<String> {
    let parent = node.parent()?;

    for index in 0..parent.child_count() {
        let child = parent.child(index as u32)?;

        if child.id() == node.id() {
            return parent
                .field_name_for_child(index as u32)
                .map(ToOwned::to_owned);
        }
    }

    None
}

fn sibling_ordinal(node: tree_sitter::Node<'_>) -> usize {
    let Some(parent) = node.parent() else {
        return 0;
    };

    let mut ordinal = 0;
    let mut cursor = parent.walk();

    for sibling in parent.children(&mut cursor) {
        if sibling.id() == node.id() {
            return ordinal;
        }

        if sibling.kind() == node.kind() {
            ordinal += 1;
        }
    }

    ordinal
}

fn semantic_node_name(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "property_identifier" | "identifier" | "tag_name" | "attribute_name" => {
            node.utf8_text(source).ok().map(ToOwned::to_owned)
        }
        _ => None,
    }
}

fn node_text_fragment(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    const MAX_FRAGMENT_CHARS: usize = 96;

    let text = node.utf8_text(source).ok()?.trim();

    if text.is_empty() {
        return None;
    }

    Some(text.chars().take(MAX_FRAGMENT_CHARS).collect())
}

fn javascript_property_anchor(
    mut node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<String> {
    loop {
        match node.kind() {
            "pair" | "property_assignment" => {
                if let Some(key) = child_by_field_or_kind(node, source, "key", &[
                    "property_identifier",
                    "identifier",
                    "string",
                ]) {
                    return clean_js_property_name(key.utf8_text(source).ok()?);
                }
            }
            "assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    return assignment_property_name(left, source);
                }
            }
            _ => {}
        }

        node = node.parent()?;
    }
}

fn assignment_property_name(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "member_expression" => {
            let property = node.child_by_field_name("property")?;
            property.utf8_text(source).ok().map(ToOwned::to_owned)
        }
        "identifier" => node.utf8_text(source).ok().map(ToOwned::to_owned),
        _ => None,
    }
}

fn clean_js_property_name(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('"').trim_matches('\'').trim();

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn css_declaration_property_anchor(
    mut node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<String> {
    loop {
        if node.kind() == "declaration"
            && let Some(property) = child_by_field_or_kind(node, source, "property", &[
            "property_name",
            "plain_value",
            "identifier",
        ]) {
            return property.utf8_text(source).ok().map(|value| value.trim().to_string());
        }

        node = node.parent()?;
    }
}

fn html_attribute_anchor(
    mut node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<(Option<String>, String)> {
    loop {
        if node.kind() == "attribute" {
            let attribute = child_by_field_or_kind(node, source, "name", &["attribute_name"])?
                .utf8_text(source)
                .ok()?
                .trim()
                .to_string();

            let element = html_element_name(node, source);

            return Some((element, attribute));
        }

        node = node.parent()?;
    }
}

fn html_element_name(
    mut node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<String> {
    loop {
        if matches!(node.kind(), "start_tag" | "self_closing_tag" | "element") {
            let mut cursor = node.walk();

            for child in node.children(&mut cursor) {
                if child.kind() == "tag_name" {
                    return child.utf8_text(source).ok().map(|value| value.trim().to_string());
                }
            }
        }

        node = node.parent()?;
    }
}

fn child_by_field_or_kind<'a>(
    node: tree_sitter::Node<'a>,
    source: &[u8],
    field_name: &str,
    kinds: &[&str],
) -> Option<tree_sitter::Node<'a>> {
    if let Some(child) = node.child_by_field_name(field_name) {
        return Some(child);
    }

    let mut cursor = node.walk();

    node.children(&mut cursor)
        .find(|child| {
            kinds.contains(&child.kind())
                && child.utf8_text(source).is_ok_and(|text| !text.trim().is_empty())
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RewriteTarget {
    WholeBody,
    TextRange {
        start: usize,
        end: usize,
    },
    JsonPointer(String),
    AstPath(Vec<AstPathSegment>),
    Selector(String),
    TextAnchor(String),
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_javascript_property_anchor_with_tree_sitter() {
        let original = r#"window.config = { apiBase: "https://old.example.com" };"#;
        let edited = r#"window.config = { apiBase: "https://new.example.com" };"#;

        let intent = extract_body_rewrite_intent(
            original,
            edited,
            Some("application/javascript"),
        )
            .expect("javascript edit should produce intent");

        assert_eq!(intent.language, BodyLanguage::JavaScript);
        assert_eq!(intent.confidence, RewriteConfidence::High);
        assert_eq!(
            intent.anchor,
            BodyAnchor::JsProperty {
                property: "apiBase".to_string(),
            },
        );
        assert_eq!(
            intent.operation,
            BodyRewriteOperation::ReplaceJsProperty {
                property: "apiBase".to_string(),
                old: r#""https://old.example.com""#.to_string(),
                new: r#""https://new.example.com""#.to_string(),
            },
        );
    }

    #[test]
    fn extracts_css_declaration_anchor_with_tree_sitter() {
        let original = "body { color: red; }";
        let edited = "body { color: blue; }";

        let intent = extract_body_rewrite_intent(original, edited, Some("text/css"))
            .expect("css edit should produce intent");

        assert_eq!(intent.language, BodyLanguage::Css);
        assert_eq!(intent.confidence, RewriteConfidence::High);
        assert_eq!(
            intent.anchor,
            BodyAnchor::CssDeclaration {
                property: "color".to_string(),
            },
        );
        assert_eq!(
            intent.operation,
            BodyRewriteOperation::ReplaceCssDeclaration {
                property: "color".to_string(),
                old: "red".to_string(),
                new: "blue".to_string(),
            },
        );
    }

    #[test]
    fn extracts_html_attribute_anchor_with_tree_sitter() {
        let original = r#"<script src="https://old.example.com/app.js"></script>"#;
        let edited = r#"<script src="https://new.example.com/app.js"></script>"#;

        let intent = extract_body_rewrite_intent(original, edited, Some("text/html"))
            .expect("html edit should produce intent");

        assert_eq!(intent.language, BodyLanguage::Html);
        assert_eq!(intent.confidence, RewriteConfidence::High);
        assert_eq!(
            intent.anchor,
            BodyAnchor::HtmlAttribute {
                element: Some("script".to_string()),
                attribute: "src".to_string(),
            },
        );
        assert_eq!(
            intent.operation,
            BodyRewriteOperation::ReplaceHtmlAttribute {
                selector: "script".to_string(),
                attribute: "src".to_string(),
                old: "old".to_string(),
                new: "new".to_string(),
            },
        );
    }
}