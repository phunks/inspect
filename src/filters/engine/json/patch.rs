use std::fmt::Write;

use sqlx::types::JsonValue;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratedJsonPatchOperation {
    Add {
        path: String,
        value: String,
    },
    Remove {
        path: String,
    },
    Replace {
        path: String,
        value: String,
    },
    Move {
        from: String,
        path: String,
    },
}

impl GeneratedJsonPatchOperation {
    pub fn to_rfc6902_value(&self) -> JsonValue {
        match self {
            Self::Add { path, value } => serde_json::json!({
                "op": "add",
                "path": path,
                "value": parse_json_patch_value(value),
            }),
            Self::Remove { path } => serde_json::json!({
                "op": "remove",
                "path": path,
            }),
            Self::Replace { path, value } => serde_json::json!({
                "op": "replace",
                "path": path,
                "value": parse_json_patch_value(value),
            }),
            Self::Move { from, path } => serde_json::json!({
                "op": "move",
                "from": from,
                "path": path,
            }),
        }
    }

    pub fn from_rfc6902_value(value: &JsonValue) -> Option<Self> {
        let op = value.get("op")?.as_str()?;

        match op {
            "add" => Some(Self::Add {
                path: value.get("path")?.as_str()?.to_string(),
                value: json_patch_value_to_string(value.get("value")?),
            }),
            "remove" => Some(Self::Remove {
                path: value.get("path")?.as_str()?.to_string(),
            }),
            "replace" => Some(Self::Replace {
                path: value.get("path")?.as_str()?.to_string(),
                value: json_patch_value_to_string(value.get("value")?),
            }),
            "move" => Some(Self::Move {
                from: value.get("from")?.as_str()?.to_string(),
                path: value.get("path")?.as_str()?.to_string(),
            }),
            _ => None,
        }
    }
}

pub fn json_patch_operations_to_rfc6902_json(
    operations: &[GeneratedJsonPatchOperation],
) -> String {
    let values = operations
        .iter()
        .map(GeneratedJsonPatchOperation::to_rfc6902_value)
        .collect::<Vec<_>>();

    serde_json::to_string_pretty(&values)
        .unwrap_or_else(|_| "[]".to_string())
}

pub fn json_patch_operations_from_rfc6902_json(
    patch_json: &str,
) -> Vec<GeneratedJsonPatchOperation> {
    let Ok(JsonValue::Array(values)) = serde_json::from_str::<JsonValue>(patch_json) else {
        return Vec::new();
    };

    values
        .iter()
        .filter_map(GeneratedJsonPatchOperation::from_rfc6902_value)
        .collect()
}

pub fn diff_json_patch_operations(
    original: &str,
    edited: &str,
) -> Option<Vec<GeneratedJsonPatchOperation>> {
    let original = serde_json::from_str::<JsonValue>(original).ok()?;
    let edited = serde_json::from_str::<JsonValue>(edited).ok()?;

    let patch = json_patch::diff(&original, &edited);
    let patch_json = serde_json::to_string(&patch).ok()?;

    Some(json_patch_operations_from_rfc6902_json(&patch_json))
}

pub fn diff_json_patch_rfc6902_json(
    original: &str,
    edited: &str,
) -> Option<String> {
    let original = serde_json::from_str::<JsonValue>(original).ok()?;
    let edited = serde_json::from_str::<JsonValue>(edited).ok()?;

    let patch = json_patch::diff(&original, &edited);

    serde_json::to_string_pretty(&patch).ok()
}

pub fn apply_json_patch_rfc6902_json(
    original: &str,
    patch_json: &str,
) -> Option<String> {
    let mut value = serde_json::from_str::<JsonValue>(original).ok()?;
    let patch = serde_json::from_str::<json_patch::Patch>(patch_json).ok()?;

    json_patch::patch(&mut value, &patch).ok()?;

    serde_json::to_string(&value).ok()
}

pub fn apply_json_merge_patch_json(
    original: &str,
    merge_patch_json: &str,
) -> Option<String> {
    let mut value = serde_json::from_str::<JsonValue>(original).ok()?;
    let patch = serde_json::from_str::<JsonValue>(merge_patch_json).ok()?;

    json_patch::merge(&mut value, &patch);

    serde_json::to_string(&value).ok()
}

pub fn validate_json_patch_operations(
    original: &str,
    edited: &str,
    operations: &[GeneratedJsonPatchOperation],
) -> bool {
    let patch_json = json_patch_operations_to_rfc6902_json(operations);

    let Some(patched) = apply_json_patch_rfc6902_json(original, &patch_json) else {
        return false;
    };

    let Ok(patched) = serde_json::from_str::<JsonValue>(&patched) else {
        return false;
    };

    let Ok(edited) = serde_json::from_str::<JsonValue>(edited) else {
        return false;
    };

    patched == edited
}

pub fn write_json_patch_comments(out: &mut String, operations: &[GeneratedJsonPatchOperation]) {
    out.push_str("\n            // JSON patch operations:");

    for operation in operations {
        match operation {
            GeneratedJsonPatchOperation::Add { path, value } => {
                write!(out, "\n            // - add {} = {}", path, value)
                    .expect("write to String should not fail");
            }
            GeneratedJsonPatchOperation::Remove { path } => {
                write!(out, "\n            // - remove {}", path)
                    .expect("write to String should not fail");
            }
            GeneratedJsonPatchOperation::Replace { path, value } => {
                write!(out, "\n            // - replace {} = {}", path, value)
                    .expect("write to String should not fail");
            }
            GeneratedJsonPatchOperation::Move { from, path } => {
                write!(out, "\n            // - move {} -> {}", from, path)
                    .expect("write to String should not fail");
            }
        }
    }

    let patch_json = json_patch_operations_to_rfc6902_json(operations);

    out.push_str("\n            // RFC6902 JSON Patch:");

    for line in patch_json.lines() {
        out.push_str("\n            // ");
        out.push_str(line);
    }
}

fn parse_json_patch_value(value: &str) -> JsonValue {
    serde_json::from_str::<JsonValue>(value)
        .unwrap_or_else(|_| JsonValue::String(value.to_string()))
}

fn json_patch_value_to_string(value: &JsonValue) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_patch_crate_diff_generates_operations() {
        let operations = diff_json_patch_operations(
            r#"{"user":{"name":"alice","enabled":true}}"#,
            r#"{"user":{"name":"bob","enabled":true}}"#,
        )
            .expect("valid json should diff");

        assert_eq!(
            operations,
            vec![GeneratedJsonPatchOperation::Replace {
                path: "/user/name".to_string(),
                value: r#""bob""#.to_string(),
            }],
        );
    }

    #[test]
    fn json_patch_crate_apply_validates_operations() {
        let operations = vec![GeneratedJsonPatchOperation::Replace {
            path: "/user/name".to_string(),
            value: r#""bob""#.to_string(),
        }];

        assert!(validate_json_patch_operations(
            r#"{"user":{"name":"alice"}}"#,
            r#"{"user":{"name":"bob"}}"#,
            &operations,
        ));
    }

    #[test]
    fn json_merge_patch_can_apply() {
        let patched = apply_json_merge_patch_json(
            r#"{"user":{"name":"alice","role":"user"}}"#,
            r#"{"user":{"role":"admin"}}"#,
        )
            .expect("merge patch should apply");

        assert_eq!(
            serde_json::from_str::<JsonValue>(&patched).unwrap(),
            serde_json::json!({
                "user": {
                    "name": "alice",
                    "role": "admin",
                },
            }),
        );
    }
}