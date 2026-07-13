use rama::{
    extensions::{ExtensionsRef, Extension},
    io::Io,
    net::address::Domain,
    telemetry::tracing,
    tls::server::{
        SniPrefixedIo,
        SniRequest,
    },
    Service,
};
use rama::error::BoxError;
use crate::mitm::proxy::AnyError;

#[derive(Debug, Clone, Extension)]
pub struct IngressSNI(pub(crate) Domain);

#[derive(Debug)]
pub struct ConnectSniRouterService<T> {
    pub(crate) https_service: T,
}

impl<T, S> Service<SniRequest<S>> for ConnectSniRouterService<T>
where
    S: Io + Unpin + ExtensionsRef,
    T: Service<SniPrefixedIo<S>, Output = (), Error: Into<AnyError>>,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        SniRequest { sni, stream }: SniRequest<S>,
    ) -> Result<Self::Output, Self::Error> {
        if let Some(sni) = sni {
            tracing::debug!(tls_sni = %sni, "peeked TLS SNI from ClientHello");
            stream.extensions().insert(IngressSNI(sni));
        } else {
            tracing::debug!("TLS ClientHello did not contain SNI");
        }

        self.https_service
            .serve(stream)
            .await
            .map_err(|err| BoxError::from(err.into()))
    }
}
