use rama::{
    error::{OpaqueError}, extensions::ExtensionsMut,
    net::{
        address::Domain,
        tls::server::{
            SniPeekStream,
            SniRequest,
        },
    },
    stream::Stream,
    telemetry::tracing,
    Service,
};
use crate::mitm::proxy::AnyError;

#[derive(Debug, Clone)]
pub struct IngressSNI(pub(crate) Domain);

#[derive(Debug)]
pub struct ConnectSniRouterService<T> {
    pub(crate) https_service: T,
}

impl<T, S> Service<SniRequest<S>> for ConnectSniRouterService<T>
where
    S: Stream + Unpin + ExtensionsMut,
    T: Service<SniPeekStream<S>, Output = (), Error: Into<AnyError>>,
{
    type Output = ();
    type Error = OpaqueError;

    async fn serve(
        &self,
        SniRequest { sni, mut stream }: SniRequest<S>,
    ) -> Result<Self::Output, Self::Error> {
        if let Some(sni) = sni {
            tracing::debug!(tls_sni = %sni, "peeked TLS SNI from ClientHello");
            stream.extensions_mut().insert(IngressSNI(sni));
        } else {
            tracing::debug!("TLS ClientHello did not contain SNI");
        }

        self.https_service
            .serve(stream)
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))
    }
}
