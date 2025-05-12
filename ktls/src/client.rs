use std::sync::Arc;


pub struct KTlsConnector {
    config: Arc<rustls::ClientConfig>,
}

impl KTlsConnector {
    pub fn new(config: Arc<rustls::ClientConfig>) -> Self {
        Self { config }
    }

    // pub async fn try_connect<IO>(
    //     &self,
    //     domain: ServerName<'static>,
    //     stream: IO
    // ) -> Result<
}

// pub struct KTlsClientStream

// pub struct TryConnectError<IO> {
//     connection: 
// }
