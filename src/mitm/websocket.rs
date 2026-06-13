use std::future::Future;

use rama::{
    Service,
    error::BoxError,
    extensions::Extensions,
    futures::SinkExt,
    http::{
        Body, Request, Response, StatusCode,
        conn::TargetHttpVersion,
        headers::{
            SecWebSocketExtensions, TypedHeader as _,
        },
        io::upgrade,
        service::web::response::IntoResponse,
        ws::{
            AsyncWebSocket, Message, ProtocolError,
            handshake::client::HttpClientWebSocketExt,
            protocol::{Role, WebSocketConfig},
        },
    },
    rt::Executor,
    telemetry::tracing,
};
use rama::extensions::ExtensionsRef;

pub async fn mitm_websocket<S>(client: &S, req: Request) -> Response
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    tracing::debug!("detected websocket request: starting MITM WS upgrade...");

    let (mut parts, body) = req.into_parts();

    // Avoid negotiating permessage-deflate through the MITM for now.
    // Some peer/client combinations can produce invalid window bits for rama-ws/flate2.
    let _ = parts.headers.remove(SecWebSocketExtensions::name());

    let parts_copy = parts.clone();

    let req = Request::from_parts(parts, body);
    let guard = req
        .extensions()
        .get::<Executor>()
        .and_then(|exec| exec.guard())
        .cloned();

    let cancel = async move {
        match guard {
            Some(guard) => guard.downgrade().into_cancelled().await,
            None => std::future::pending::<()>().await,
        }
    };

    let target_version = req.version();
    tracing::debug!("forcing egress http connection as {target_version:?} to ensure WS upgrade");

    let mut extensions = Extensions::new();
    extensions.insert(TargetHttpVersion(target_version));

    let mut handshake = match client
        .websocket_with_request(req)
        .initiate_handshake(extensions)
        .await
    {
        Ok(handshake) => handshake,
        Err(err) => {
            tracing::error!("failed to initiate egress websocket handshake: {err:?}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // Keep websocket compression disabled in the MITM path.
    handshake.extensions = None;

    let egress_socket = match handshake.complete().await {
        Ok(socket) => socket,
        Err(err) => {
            tracing::error!("failed to complete egress websocket handshake: {err:?}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let (egress_socket, mut response_parts, _) = egress_socket.into_parts();

    // Do not advertise permessage-deflate to the downstream client.
    let _ = response_parts
        .headers
        .remove(SecWebSocketExtensions::name());

    let ingress_socket_cfg = WebSocketConfig::default();
    let response = Response::from_parts(response_parts, Body::empty());

    tokio::spawn(async move {
        tracing::debug!("egress websocket active: starting ingress WS upgrade...");

        let request = Request::from_parts(parts_copy, Body::empty());

        let ingress_socket = match upgrade::handle_upgrade(&request).await {
            Ok(upgraded) => {
                AsyncWebSocket::from_raw_socket(upgraded, Role::Server, Some(ingress_socket_cfg))
                    .await
            }
            Err(err) => {
                tracing::error!("error upgrading ingress websocket: {err:?}");
                return;
            }
        };

        tracing::debug!("both websockets active: MITM websocket relay started");
        relay_websockets(cancel, ingress_socket, egress_socket).await;
    });

    response
}

async fn relay_websockets<F>(
    cancel: F,
    mut ingress_socket: AsyncWebSocket,
    mut egress_socket: AsyncWebSocket,
) where
    F: Future<Output = ()>,
{
    let mut cancel = Box::pin(cancel);

    loop {
        tokio::select! {
            ingress_result = ingress_socket.recv_message() => {
                let msg = match handle_recv_result("ingress", ingress_result) {
                    Some(msg) => msg,
                    None => return,
                };

                if let Err(err) = egress_socket.send(msg).await {
                    if err.is_connection_error() {
                        tracing::debug!("egress socket disconnected ({err})");
                    } else {
                        tracing::error!("failed to relay ingress websocket message: {err}");
                    }
                    return;
                }
            }

            egress_result = egress_socket.recv_message() => {
                let msg = match handle_recv_result("egress", egress_result) {
                    Some(msg) => msg,
                    None => return,
                };

                if let Err(err) = ingress_socket.send(msg).await {
                    if err.is_connection_error() {
                        tracing::debug!("ingress socket disconnected ({err})");
                    } else {
                        tracing::error!("failed to relay egress websocket message: {err}");
                    }
                    return;
                }
            }

            _ = cancel.as_mut() => {
                tracing::debug!("shutdown initiated; dropping websocket relay");
                return;
            }
        }
    }
}

fn handle_recv_result(
    side: &'static str,
    result: Result<Message, ProtocolError>,
) -> Option<Message> {
    match result {
        Ok(msg) => Some(msg),
        Err(err) => {
            if err.is_connection_error()
                || matches!(err, ProtocolError::ResetWithoutClosingHandshake)
            {
                tracing::debug!("{side} websocket disconnected ({err})");
            } else {
                tracing::error!("{side} websocket failed: {err}");
            }

            None
        }
    }
}