use crate::filters::types::{
    FilterBodyPatch,
    FilterHeader,
    FilterMark,
    FilterRequest,
    FilterRequestPatch,
    FilterResponse,
    FilterResponsePatch,
    RequestAction,
    ResponseAction,
};

#[derive(Clone, Debug)]
pub struct RotoRequest {
    inner: FilterRequest,
}

impl RotoRequest {
    pub fn new(inner: FilterRequest) -> Self {
        Self { inner }
    }

    pub fn id(&self) -> &str {
        &self.inner.id
    }

    pub fn method(&self) -> &str {
        &self.inner.method
    }

    pub fn scheme(&self) -> &str {
        &self.inner.scheme
    }

    pub fn host(&self) -> &str {
        &self.inner.host
    }

    pub fn path(&self) -> &str {
        &self.inner.path
    }

    pub fn query(&self) -> &str {
        &self.inner.query
    }

    pub fn content_type(&self) -> Option<&str> {
        self.inner.body.content_type.as_deref()
    }

    pub fn body_text(&self) -> Option<&str> {
        self.inner.body.text.as_deref()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.inner
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    pub fn into_inner(self) -> FilterRequest {
        self.inner
    }
}

#[derive(Clone, Debug)]
pub struct RotoResponse {
    inner: FilterResponse,
}

impl RotoResponse {
    pub fn new(inner: FilterResponse) -> Self {
        Self { inner }
    }

    pub fn status(&self) -> u16 {
        self.inner.status
    }

    pub fn version(&self) -> &str {
        &self.inner.version
    }

    pub fn content_type(&self) -> Option<&str> {
        self.inner.body.content_type.as_deref()
    }

    pub fn body_text(&self) -> Option<&str> {
        self.inner.body.text.as_deref()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.inner
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    pub fn into_inner(self) -> FilterResponse {
        self.inner
    }
}

#[derive(Clone, Debug)]
pub struct RotoRequestAction {
    inner: RequestAction,
}

impl RotoRequestAction {
    pub fn pass() -> Self {
        Self {
            inner: RequestAction::pass(),
        }
    }

    pub fn stop(mut self) -> Self {
        self.inner.continue_filters = false;
        self
    }

    pub fn set_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner
            .request
            .get_or_insert_with(FilterRequestPatch::default)
            .set_headers
            .push(FilterHeader {
                name: name.into(),
                value: value.into(),
            });

        self
    }

    pub fn remove_header(mut self, name: impl Into<String>) -> Self {
        self.inner
            .request
            .get_or_insert_with(FilterRequestPatch::default)
            .remove_headers
            .push(name.into());

        self
    }

    pub fn set_path(mut self, path: impl Into<String>) -> Self {
        self.inner
            .request
            .get_or_insert_with(FilterRequestPatch::default)
            .path = Some(path.into());

        self
    }

    pub fn set_query(mut self, query: impl Into<String>) -> Self {
        self.inner
            .request
            .get_or_insert_with(FilterRequestPatch::default)
            .query = Some(query.into());

        self
    }

    pub fn set_body_text(
        mut self,
        text: impl Into<String>,
        content_type: Option<String>,
    ) -> Self {
        self.inner
            .request
            .get_or_insert_with(FilterRequestPatch::default)
            .body = Some(FilterBodyPatch {
            bytes: text.into().into_bytes(),
            content_type,
        });

        self
    }

    pub fn mark(mut self, label: impl Into<String>) -> Self {
        self.inner.marks.push(FilterMark {
            label: label.into(),
            color: None,
        });

        self
    }

    pub fn mark_color(mut self, label: impl Into<String>, color: impl Into<String>) -> Self {
        self.inner.marks.push(FilterMark {
            label: label.into(),
            color: Some(color.into()),
        });

        self
    }

    pub fn into_inner(self) -> RequestAction {
        self.inner
    }
}

#[derive(Clone, Debug)]
pub struct RotoResponseAction {
    inner: ResponseAction,
}

impl RotoResponseAction {
    pub fn pass() -> Self {
        Self {
            inner: ResponseAction::pass(),
        }
    }

    pub fn stop(mut self) -> Self {
        self.inner.continue_filters = false;
        self
    }

    pub fn set_status(mut self, status: u16) -> Self {
        self.inner
            .response
            .get_or_insert_with(FilterResponsePatch::default)
            .status = Some(status);

        self
    }

    pub fn set_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner
            .response
            .get_or_insert_with(FilterResponsePatch::default)
            .set_headers
            .push(FilterHeader {
                name: name.into(),
                value: value.into(),
            });

        self
    }

    pub fn remove_header(mut self, name: impl Into<String>) -> Self {
        self.inner
            .response
            .get_or_insert_with(FilterResponsePatch::default)
            .remove_headers
            .push(name.into());

        self
    }

    pub fn set_body_text(
        mut self,
        text: impl Into<String>,
        content_type: Option<String>,
    ) -> Self {
        self.inner
            .response
            .get_or_insert_with(FilterResponsePatch::default)
            .body = Some(FilterBodyPatch {
            bytes: text.into().into_bytes(),
            content_type,
        });

        self
    }

    pub fn mark(mut self, label: impl Into<String>) -> Self {
        self.inner.marks.push(FilterMark {
            label: label.into(),
            color: None,
        });

        self
    }

    pub fn mark_color(mut self, label: impl Into<String>, color: impl Into<String>) -> Self {
        self.inner.marks.push(FilterMark {
            label: label.into(),
            color: Some(color.into()),
        });

        self
    }

    pub fn into_inner(self) -> ResponseAction {
        self.inner
    }
}