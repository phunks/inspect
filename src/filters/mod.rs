pub mod http_client;
pub mod manager;
pub mod roto_api;
pub mod runtime;
pub mod types;
pub mod generator;
pub mod generated;
pub mod editor;
pub mod engine;
pub mod runtime_state;

pub use manager::FilterManager;
pub use runtime::{CompiledFilter, CompiledFilterSet};
pub use engine::diff::{
    DiffEvent,
    DiffNode,
    DiffPath,
    DiffPathSegment,
    DiffSource,
};

pub use engine::json::patch::{
    apply_json_merge_patch_json,
    apply_json_patch_rfc6902_json,
    diff_json_patch_operations,
    diff_json_patch_rfc6902_json,
    json_patch_operations_from_rfc6902_json,
    json_patch_operations_to_rfc6902_json,
    validate_json_patch_operations,
    write_json_patch_comments,
    GeneratedJsonPatchOperation,
};
pub use engine::semantic::{
    extract_body_rewrite_intent,
    extract_tree_sitter_anchor,
    BodyAnchor,
    BodyDiffKind,
    BodyLanguage,
    BodyRewriteIntent,
    BodyRewriteOperation,
    RewriteConfidence,
    TreeSitterAnchor,
};
pub use generated::{
    GeneratedFilterSaveResult,
    save_generated_filter_and_reload,
    save_generated_roto_source_and_reload,
};
pub use editor::{
    EditableFilterSession,
    EditableFilterSessionError,
    EditableFilterSessionPreview,
    EditableFilterSessionSaveResult,
    EditableHttpBody,
    EditableHttpHeader,
    EditableHttpMessage,
    EditableHttpMessageDiff,
    EditableHttpMessageKind,
    EditableHttpMessageParseError,
    EditedFilterGenerationError,
    extract_request_filter_from_edit,
    extract_request_rewrite_from_edit,
    extract_response_filter_from_edit,
    extract_response_rewrite_from_edit,
    generate_request_filter_from_edited_text,
    generate_response_filter_from_edited_text,
};
pub use generator::{
    GeneratedDiffAnchor,
    GeneratedDiffStrategy,
    GeneratedFilter,
    GeneratedFilterAction,
    GeneratedFilterBuilder,
    GeneratedFilterCondition,
    GeneratedFilterPhase,
    GeneratedFilterSelectionTarget,
    GeneratedFilterTrigger,
    GeneratedRewriteDraft,
    GeneratedRewriteExtractor,
    GeneratedRewriteRequest,
    GeneratedRewriteRequestInput,
    GeneratedRewriteResponse,
    GeneratedRewriteResponseInput,
};
pub use types::{
    CompletedAction,
    FilterBody,
    FilterBodyPatch,
    FilterDefinition,
    FilterFlow,
    FilterHeader,
    FilterHttpRequest,
    FilterMark,
    FilterMetadata,
    FilterPhase,
    FilterRequest,
    FilterRequestPatch,
    FilterRequestView,
    FilterResponse,
    FilterResponsePatch,
    FilterResponseView,
    FilterSyntheticResponse,
    FilterTrigger,
    RequestAction,
    ResponseAction,
};
