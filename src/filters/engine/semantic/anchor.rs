use crate::filters::engine::semantic::body_tree_sitter::{AstPathSegment, BodyLanguage};

pub enum BodyAnchor {
    ContainsText(String),
    ContainsAll(Vec<String>),

    KeyValue {
        language: BodyLanguage,
        key: String,
        old_value: Option<String>,
    },

    AstNode {
        kind: String,
        name: Option<String>,
        text_fragment: String,
    },

    AstPath {
        segments: Vec<AstPathSegment>,
    },

    TextRange {
        before: String,
        after: String,
    },
}

// pub enum BodyRewriteOperation {
//     ReplaceWholeBody { ... },
//     ReplaceText { old, new },
//     InsertText { anchor, text },
//     DeleteText { text },
//     JsonPatch { ... },
// }