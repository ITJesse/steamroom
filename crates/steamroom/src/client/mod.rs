/// Background receive loop and request/response routing.
pub mod dispatch;
/// Client message construction and header encoding.
pub mod msg;
/// Multi-message unpacking (gzip-compressed message batches).
pub mod multi;

use self::dispatch::Channel;
use self::dispatch::Dispatcher;
pub use self::dispatch::EVENT_BUFFER;
pub use self::dispatch::Job;
pub use self::dispatch::JobId;
use self::dispatch::Tasks;
use self::msg::ClientMsg;
use crate::apps::AccessToken;
use crate::apps::AppInfo;
use crate::apps::PackageInfo;
use crate::auth::AuthClientId;
use crate::auth::AuthSession;
use crate::auth::AuthTokens;
use crate::auth::GuardType;
use crate::auth::PollInterval;
use crate::auth::QrAuthSession;
use crate::cdn::CdnServer;
use crate::content::CdnAuthToken;
use crate::depot::AppId;
use crate::depot::CellId;
use crate::depot::DepotId;
use crate::depot::DepotKey;
use crate::depot::ManifestId;
use crate::depot::PackageId;
use crate::error::ConnectionError;
use crate::error::Error;
use crate::generated;
use crate::messages::header;
use crate::messages::header::PacketHeader;
use crate::types::SteamId;

use crate::messages::EMsg;
use crate::messages::RawEMsg;
use crate::transport::Transport;
use bytes::Bytes;
use prost::Message;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use tracing::debug;

pub const PROTOCOL_VERSION: u32 = 65581;

struct ClientInner {
    channel: Arc<Channel>,
    dispatcher: Arc<Dispatcher>,
    steam_id: AtomicU64,
    session_id: AtomicI32,
    source_job_id: AtomicU64,
    /// Receive loop (and, once logged in, the heartbeat). Dropped, and so
    /// aborted, with the last client handle.
    tasks: Tasks,
}

pub struct SteamClient<S: Clone> {
    inner: Arc<ClientInner>,
    _state: S,
}

impl<S: Clone> Clone for SteamClient<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            _state: self._state.clone(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Disconnected;
#[derive(Clone, Copy)]
pub struct Connected;
#[derive(Clone, Copy)]
pub struct Encrypted;
#[derive(Clone, Copy)]
pub struct Ready;
#[derive(Clone, Copy)]
pub struct LoggedIn;

pub type DisconnectedClient = SteamClient<Disconnected>;

#[derive(Clone, Debug)]
pub struct IncomingMsg {
    pub emsg: EMsg,
    pub is_protobuf: bool,
    pub header: generated::CMsgProtoBufHeader,
    pub body: Bytes,
}

pub struct ServiceResponse {
    pub body: Bytes,
}

impl ServiceResponse {
    pub fn decode<M: Message + Default>(&self) -> Result<M, prost::DecodeError> {
        M::decode(&*self.body)
    }
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        // A `Job` can outlive the client; closing wakes it with
        // "disconnected" now that nothing will receive its responses.
        self.dispatcher.close();
    }
}

impl ClientInner {
    fn new(transport: Arc<dyn Transport>) -> Arc<Self> {
        Arc::new(ClientInner {
            channel: Arc::new(Channel {
                transport,
                cipher: OnceLock::new(),
            }),
            dispatcher: Dispatcher::new(),
            steam_id: AtomicU64::new(0),
            session_id: AtomicI32::new(0),
            source_job_id: AtomicU64::new(1),
            tasks: Tasks::default(),
        })
    }

    /// Hand the receive side of the transport to the background loop. Called
    /// once the connection no longer needs synchronous reads (after the TCP
    /// encryption handshake, or immediately for WebSocket).
    fn start_receiving(&self) {
        let task = tokio::spawn(dispatch::receive_loop(
            Arc::clone(&self.channel),
            Arc::clone(&self.dispatcher),
        ));
        self.tasks.push(task.abort_handle());
    }

    async fn send_raw(&self, msg: &ClientMsg<'_>) -> Result<(), Error> {
        if self.dispatcher.is_closed() {
            return Err(ConnectionError::Disconnected.into());
        }
        self.channel.send(&msg.to_bytes()).await
    }

    fn next_job_id(&self) -> JobId {
        JobId(self.source_job_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Register a job for `msg`, then send it. The job is registered first so
    /// a fast response cannot arrive before anyone is listening for it.
    async fn send_job(&self, msg: &mut ClientMsg<'_>) -> Result<Job, Error> {
        let job = self.dispatcher.register_job(self.next_job_id())?;
        msg.header.jobid_source = Some(job.id().0);
        self.send_raw(msg).await?;
        Ok(job)
    }

    async fn call_service(
        &self,
        mut msg: ClientMsg<'_>,
        method_name: &str,
    ) -> Result<ServiceResponse, Error> {
        msg.header.target_job_name = Some(method_name.to_string());
        let mut job = self.send_job(&mut msg).await?;
        let incoming = job.recv_expect(EMsg::SERVICE_METHOD_RESPONSE).await?;
        check_service_eresult(&incoming)?;
        Ok(ServiceResponse {
            body: incoming.body,
        })
    }

    async fn send_hello(&self) -> Result<(), Error> {
        let hello = generated::CMsgClientHello {
            protocol_version: Some(PROTOCOL_VERSION),
        };
        let body = hello.encode_to_vec();
        let msg = ClientMsg::with_body(EMsg::CLIENT_HELLO, &body);
        self.send_raw(&msg).await
    }
}

impl<S: Clone> SteamClient<S> {
    /// Messages that are not a response to a request made through this client:
    /// license list, account info, persona state, CM list, service
    /// notifications, logoff. Every receiver returned here shares one queue,
    /// so each message is delivered to one of them.
    ///
    /// The queue holds the last [`EVENT_BUFFER`] messages, so pushes that
    /// arrive with the logon response can still be read after `login`
    /// returns. Once the connection closes, receivers drain what is buffered
    /// and then report the channel closed.
    pub fn events(&self) -> async_channel::Receiver<IncomingMsg> {
        self.inner.dispatcher.events()
    }

    /// False once the receive loop has stopped (the CM closed the connection
    /// or the transport failed). Requests fail immediately from then on.
    pub fn is_connected(&self) -> bool {
        !self.inner.dispatcher.is_closed()
    }
}

impl SteamClient<Disconnected> {
    /// Wrap a TCP-style transport. Nothing is read until
    /// [`encrypt`](SteamClient::encrypt) runs the channel handshake.
    pub async fn connect<T: Transport>(
        transport: T,
    ) -> Result<(SteamClient<Connected>, async_channel::Receiver<IncomingMsg>), Error> {
        let inner = ClientInner::new(Arc::new(transport));
        let events = inner.dispatcher.events();
        Ok((
            SteamClient {
                inner,
                _state: Connected,
            },
            events,
        ))
    }

    /// Connect via WebSocket -- skips encryption handshake (TLS handles it).
    /// Messages are sent/received as plaintext over the WebSocket.
    pub async fn connect_ws<T: Transport>(
        transport: T,
    ) -> Result<(SteamClient<Encrypted>, async_channel::Receiver<IncomingMsg>), Error> {
        let inner = ClientInner::new(Arc::new(transport));
        inner.start_receiving();
        let events = inner.dispatcher.events();
        Ok((
            SteamClient {
                inner,
                _state: Encrypted,
            },
            events,
        ))
    }
}

impl SteamClient<Connected> {
    pub async fn encrypt(self) -> Result<SteamClient<Encrypted>, Error> {
        let transport = &self.inner.channel.transport;
        debug!("waiting for ChannelEncryptRequest...");
        // Wait for ChannelEncryptRequest
        let data = transport.recv().await?;
        debug!("received {} bytes", data.len());
        let parsed = header::PacketHeader::parse(&data)?;
        let (emsg, body) = match parsed {
            PacketHeader::Simple { header, body } => (header.emsg, body),
            _ => return Err(ConnectionError::EncryptionFailed.into()),
        };

        if emsg != EMsg::CHANNEL_ENCRYPT_REQUEST {
            return Err(ConnectionError::UnexpectedEMsg {
                expected: EMsg::CHANNEL_ENCRYPT_REQUEST,
                got: emsg,
            }
            .into());
        }

        // Generate session key
        let mut session_key = [0u8; 32];
        getrandom::fill(&mut session_key).expect("RNG failed");

        // The body contains: protocol version (u32) + universe (u32) + optional nonce (16 bytes)
        // We need to encrypt (session_key + nonce) with Steam's RSA public key
        let nonce = if body.len() > 8 {
            &body[8..]
        } else {
            &[] as &[u8]
        };

        let mut plaintext = Vec::with_capacity(32 + nonce.len());
        plaintext.extend_from_slice(&session_key);
        plaintext.extend_from_slice(nonce);
        let encrypted_key = crate::crypto::rsa::encrypt_with_steam_public_key(&plaintext)?;

        // Build ChannelEncryptResponse
        // Layout: protocol_version(u32) + key_size(u32) + encrypted_key + crc32 + trailing_zeros(u32)
        let mut response_body = Vec::new();
        response_body.extend_from_slice(&1u32.to_le_bytes()); // protocol version
        response_body.extend_from_slice(&(encrypted_key.len() as u32).to_le_bytes());
        response_body.extend_from_slice(&encrypted_key);
        let crc = crc32fast::hash(&encrypted_key);
        response_body.extend_from_slice(&crc.to_le_bytes());
        response_body.extend_from_slice(&0u32.to_le_bytes());

        // Send as simple (non-protobuf) message
        let mut packet = Vec::new();
        let raw = RawEMsg::without_proto(EMsg::CHANNEL_ENCRYPT_RESPONSE);
        packet.extend_from_slice(&raw.0.to_le_bytes());
        packet.extend_from_slice(&u64::MAX.to_le_bytes()); // target_job_id
        packet.extend_from_slice(&u64::MAX.to_le_bytes()); // source_job_id
        packet.extend_from_slice(&response_body);

        debug!(
            "encrypt response packet ({} bytes): {:02x?}",
            packet.len(),
            &packet[..std::cmp::min(64, packet.len())]
        );
        transport.send(&packet).await?;

        // Wait for ChannelEncryptResult
        let data = transport.recv().await?;
        let parsed = header::PacketHeader::parse(&data)?;
        let (emsg, body) = match parsed {
            PacketHeader::Simple { header, body } => (header.emsg, body),
            _ => return Err(ConnectionError::EncryptionFailed.into()),
        };

        if emsg != EMsg::CHANNEL_ENCRYPT_RESULT {
            return Err(ConnectionError::UnexpectedEMsg {
                expected: EMsg::CHANNEL_ENCRYPT_RESULT,
                got: emsg,
            }
            .into());
        }

        if body.len() >= 4 {
            let code = u32::from_le_bytes(body[..4].try_into().unwrap()) as i32;
            debug!("ChannelEncryptResult code={code}");
            crate::enums::eresult(code).map_err(|_| ConnectionError::EncryptionFailed)?;
        }

        // Store the session cipher
        let cipher = crate::connection::encryption::SessionCipher::new(session_key);
        let _ = self.inner.channel.cipher.set(cipher);
        self.inner.start_receiving();

        debug!("encryption handshake complete");
        Ok(SteamClient {
            inner: self.inner,
            _state: Encrypted,
        })
    }
}

impl SteamClient<Encrypted> {
    /// Send `CMsgClientHello` and transition to [`Ready`].
    ///
    /// Steam requires a hello message before any service-method call. Calling
    /// `prepare` is the only thing you can do in the `Encrypted` state.
    pub async fn prepare(self) -> Result<SteamClient<Ready>, Error> {
        self.inner.send_hello().await?;
        Ok(SteamClient {
            inner: self.inner,
            _state: Ready,
        })
    }
}

impl SteamClient<Ready> {
    /// Send `CMsgClientLogon` and wait for the logon response. Other messages
    /// that arrive meanwhile, including ones in the same `MULTI` as the
    /// response, go to [`events`](SteamClient::events).
    pub async fn login(
        self,
        msg: ClientMsg<'_>,
    ) -> Result<(SteamClient<LoggedIn>, IncomingMsg), Error> {
        let response = self
            .inner
            .dispatcher
            .wait_for_emsg(EMsg::CLIENT_LOG_ON_RESPONSE)?;
        self.inner.send_raw(&msg).await?;
        let incoming = response.await.map_err(|_| ConnectionError::Disconnected)?;

        let resp = generated::CMsgClientLogonResponse::decode(&*incoming.body)?;
        crate::enums::eresult(
            resp.eresult
                .ok_or(ConnectionError::MissingField("eresult"))?,
        )
        .map_err(ConnectionError::LogonFailed)?;

        if let Some(sid) = incoming.header.steamid {
            self.inner.steam_id.store(sid, Ordering::Relaxed);
        }
        if let Some(session_id) = incoming.header.client_sessionid {
            self.inner.session_id.store(session_id, Ordering::Relaxed);
        }

        debug!(
            "logged in, steamid={}",
            self.inner.steam_id.load(Ordering::Relaxed)
        );

        Ok((
            SteamClient {
                inner: self.inner,
                _state: LoggedIn,
            },
            incoming,
        ))
    }

    pub async fn send_msg(&self, msg: &ClientMsg<'_>) -> Result<(), Error> {
        self.inner.send_raw(msg).await
    }

    /// Send `msg` as a job: `jobid_source` is assigned here, and every
    /// response addressed to it is delivered to the returned [`Job`].
    pub async fn send_job(&self, mut msg: ClientMsg<'_>) -> Result<Job, Error> {
        self.inner.send_job(&mut msg).await
    }

    pub async fn call_service_method_non_authed(
        &self,
        method_name: &str,
        body: &[u8],
    ) -> Result<ServiceResponse, Error> {
        let msg = ClientMsg::with_body(EMsg::SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED, body);
        self.inner.call_service(msg, method_name).await
    }

    pub async fn get_password_rsa_public_key(
        &self,
        account_name: &str,
    ) -> Result<generated::CAuthenticationGetPasswordRsaPublicKeyResponse, Error> {
        let req = generated::CAuthenticationGetPasswordRsaPublicKeyRequest {
            account_name: Some(account_name.to_string()),
        };
        let resp = self
            .call_service_method_non_authed(
                "Authentication.GetPasswordRSAPublicKey#1",
                &req.encode_to_vec(),
            )
            .await?;
        Ok(resp.decode()?)
    }

    pub async fn begin_auth_session_via_credentials(
        &self,
        request: generated::CAuthenticationBeginAuthSessionViaCredentialsRequest,
    ) -> Result<AuthSession, Error> {
        let resp = self
            .call_service_method_non_authed(
                "Authentication.BeginAuthSessionViaCredentials#1",
                &request.encode_to_vec(),
            )
            .await?;
        let r: generated::CAuthenticationBeginAuthSessionViaCredentialsResponse = resp.decode()?;
        Ok(AuthSession {
            client_id: r.client_id.map(AuthClientId::new),
            request_id: r.request_id,
            poll_interval: r.interval.map(PollInterval::from_secs_f32),
            allowed_confirmations: r
                .allowed_confirmations
                .iter()
                .filter_map(|c| guard_type_from_proto(c.confirmation_type))
                .collect(),
            steam_id: r.steamid.map(SteamId::new),
        })
    }

    pub async fn begin_auth_session_via_qr(
        &self,
        request: generated::CAuthenticationBeginAuthSessionViaQrRequest,
    ) -> Result<QrAuthSession, Error> {
        let resp = self
            .call_service_method_non_authed(
                "Authentication.BeginAuthSessionViaQR#1",
                &request.encode_to_vec(),
            )
            .await?;
        let r: generated::CAuthenticationBeginAuthSessionViaQrResponse = resp.decode()?;
        Ok(QrAuthSession {
            client_id: r.client_id.map(AuthClientId::new),
            request_id: r.request_id,
            challenge_url: r.challenge_url,
            poll_interval: r.interval.map(PollInterval::from_secs_f32),
            allowed_confirmations: r
                .allowed_confirmations
                .iter()
                .filter_map(|c| guard_type_from_proto(c.confirmation_type))
                .collect(),
        })
    }

    pub async fn poll_auth_session(
        &self,
        client_id: AuthClientId,
        request_id: &[u8],
    ) -> Result<Option<AuthTokens>, Error> {
        let req = generated::CAuthenticationPollAuthSessionStatusRequest {
            client_id: Some(client_id.raw()),
            request_id: Some(request_id.to_vec()),
            ..Default::default()
        };
        let resp = self
            .call_service_method_non_authed(
                "Authentication.PollAuthSessionStatus#1",
                &req.encode_to_vec(),
            )
            .await?;
        let r: generated::CAuthenticationPollAuthSessionStatusResponse = resp.decode()?;
        if let (Some(access), Some(refresh)) = (r.access_token.as_ref(), r.refresh_token.as_ref())
            && !access.is_empty()
        {
            return Ok(Some(AuthTokens {
                access_token: access.clone(),
                refresh_token: refresh.clone(),
                account_name: r.account_name,
            }));
        }
        Ok(None)
    }

    pub async fn submit_steam_guard_code(
        &self,
        client_id: AuthClientId,
        steam_id: SteamId,
        code: &str,
        code_type: GuardType,
    ) -> Result<(), Error> {
        let req = generated::CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest {
            client_id: Some(client_id.raw()),
            steamid: Some(steam_id.raw()),
            code: Some(code.to_string()),
            code_type: Some(code_type.to_proto()),
        };
        self.call_service_method_non_authed(
            "Authentication.UpdateAuthSessionWithSteamGuardCode#1",
            &req.encode_to_vec(),
        )
        .await?;
        Ok(())
    }
}

impl SteamClient<LoggedIn> {
    fn make_msg<'a>(&self, emsg: EMsg, body: &'a [u8]) -> ClientMsg<'a> {
        let mut msg = ClientMsg::with_body(emsg, body);
        msg.header.steamid = Some(self.inner.steam_id.load(Ordering::Relaxed));
        msg.header.client_sessionid = Some(self.inner.session_id.load(Ordering::Relaxed));
        msg
    }

    pub async fn send_msg(&self, msg: &ClientMsg<'_>) -> Result<(), Error> {
        self.inner.send_raw(msg).await
    }

    /// Send `msg` as a job: `jobid_source` is assigned here, and every
    /// response addressed to it is delivered to the returned [`Job`].
    pub async fn send_job(&self, mut msg: ClientMsg<'_>) -> Result<Job, Error> {
        self.inner.send_job(&mut msg).await
    }

    /// Send a request and return its single response, which must carry
    /// `response`.
    async fn request(&self, emsg: EMsg, body: &[u8], response: EMsg) -> Result<IncomingMsg, Error> {
        let mut msg = self.make_msg(emsg, body);
        let mut job = self.inner.send_job(&mut msg).await?;
        job.recv_expect(response).await
    }

    /// Send a PICS product info request and collect every part of the answer.
    /// Steam splits large answers into several responses to the same job and
    /// sets `response_pending` on all but the last.
    async fn product_info(
        &self,
        req: &generated::CMsgClientPicsProductInfoRequest,
    ) -> Result<Vec<generated::CMsgClientPicsProductInfoResponse>, Error> {
        let body = req.encode_to_vec();
        let mut msg = self.make_msg(EMsg::CLIENT_PICS_PRODUCT_INFO_REQUEST, &body);
        let mut job = self.inner.send_job(&mut msg).await?;
        let mut parts = Vec::new();
        loop {
            let incoming = job
                .recv_expect(EMsg::CLIENT_PICS_PRODUCT_INFO_RESPONSE)
                .await?;
            let part = generated::CMsgClientPicsProductInfoResponse::decode(&*incoming.body)?;
            let pending = part.response_pending == Some(true);
            parts.push(part);
            if !pending {
                return Ok(parts);
            }
        }
    }

    pub async fn send_heartbeat(&self) -> Result<(), Error> {
        let msg = self.make_msg(EMsg::CLIENT_HEART_BEAT, &[]);
        self.inner.send_raw(&msg).await
    }

    pub async fn call_service_method(
        &self,
        method_name: &str,
        body: &[u8],
    ) -> Result<ServiceResponse, Error> {
        let msg = self.make_msg(EMsg::SERVICE_METHOD_CALL_FROM_CLIENT, body);
        self.inner.call_service(msg, method_name).await
    }

    pub async fn pics_get_access_tokens(
        &self,
        app_ids: &[AppId],
    ) -> Result<Vec<AccessToken>, Error> {
        let req = generated::CMsgClientPicsAccessTokenRequest {
            appids: app_ids.iter().map(|a| a.0).collect(),
            ..Default::default()
        };
        let incoming = self
            .request(
                EMsg::CLIENT_PICS_ACCESS_TOKEN_REQUEST,
                &req.encode_to_vec(),
                EMsg::CLIENT_PICS_ACCESS_TOKEN_RESPONSE,
            )
            .await?;
        let resp = generated::CMsgClientPicsAccessTokenResponse::decode(&*incoming.body)?;
        Ok(resp
            .app_access_tokens
            .iter()
            .map(|t| AccessToken {
                app_id: AppId(t.appid.unwrap_or(0)), // appid echoed back from our request
                token: t.access_token.unwrap_or(0),  // 0 = no token needed (free app)
            })
            .collect())
    }

    pub async fn pics_get_product_info(&self, apps: &[AccessToken]) -> Result<Vec<AppInfo>, Error> {
        let req = generated::CMsgClientPicsProductInfoRequest {
            apps: apps
                .iter()
                .map(
                    |a| generated::c_msg_client_pics_product_info_request::AppInfo {
                        appid: Some(a.app_id.0),
                        access_token: Some(a.token),
                        ..Default::default()
                    },
                )
                .collect(),
            meta_data_only: Some(false),
            ..Default::default()
        };
        let parts = self.product_info(&req).await?;
        Ok(parts
            .iter()
            .flat_map(|part| &part.apps)
            .map(|a| AppInfo {
                app_id: a.appid.map(AppId),
                change_number: a.change_number,
                kv_data: a.buffer.clone(),
            })
            .collect())
    }

    /// Fetch an app's PICS product info and decode it into a [`KeyValue`]
    /// tree. Wraps the access-token + product-info round trip.
    ///
    /// [`KeyValue`]: crate::types::key_value::KeyValue
    pub async fn app_key_values(
        &self,
        app_id: AppId,
    ) -> Result<crate::types::key_value::KeyValue, Error> {
        let tokens = self.pics_get_access_tokens(&[app_id]).await?;
        // A missing access token means the app is free / needs no token.
        let token = tokens
            .into_iter()
            .next()
            .unwrap_or(AccessToken { app_id, token: 0 });
        let infos = self.pics_get_product_info(&[token]).await?;
        let info = infos
            .into_iter()
            .next()
            .ok_or(crate::apps::KvDecodeError::Missing)?;
        Ok(info.key_values()?)
    }

    /// Fetch an app's PICS product info and decode it into a typed
    /// [`AppDetails`](crate::apps::AppDetails) (name, type, depots, branches).
    pub async fn app_details(&self, app_id: AppId) -> Result<crate::apps::AppDetails, Error> {
        let kv = self.app_key_values(app_id).await?;
        Ok(crate::apps::AppDetails::from_key_values(app_id, kv))
    }

    pub async fn pics_get_package_access_tokens(
        &self,
        package_ids: &[PackageId],
    ) -> Result<Vec<(PackageId, u64)>, Error> {
        let req = generated::CMsgClientPicsAccessTokenRequest {
            packageids: package_ids.iter().map(|p| p.0).collect(),
            ..Default::default()
        };
        let incoming = self
            .request(
                EMsg::CLIENT_PICS_ACCESS_TOKEN_REQUEST,
                &req.encode_to_vec(),
                EMsg::CLIENT_PICS_ACCESS_TOKEN_RESPONSE,
            )
            .await?;
        let resp = generated::CMsgClientPicsAccessTokenResponse::decode(&*incoming.body)?;
        Ok(resp
            .package_access_tokens
            .iter()
            .map(|t| {
                (
                    PackageId(t.packageid.unwrap_or(0)),
                    t.access_token.unwrap_or(0),
                )
            })
            .collect())
    }

    pub async fn pics_get_package_info(
        &self,
        package_ids: &[PackageId],
    ) -> Result<Vec<PackageInfo>, Error> {
        let req = generated::CMsgClientPicsProductInfoRequest {
            packages: package_ids
                .iter()
                .map(
                    |p| generated::c_msg_client_pics_product_info_request::PackageInfo {
                        packageid: Some(p.0),
                        access_token: Some(0),
                    },
                )
                .collect(),
            meta_data_only: Some(false),
            ..Default::default()
        };
        let parts = self.product_info(&req).await?;
        debug!(
            "package response: {} packages in {} part(s), unknown: {:?}",
            parts.iter().map(|p| p.packages.len()).sum::<usize>(),
            parts.len(),
            parts
                .iter()
                .flat_map(|p| &p.unknown_packageids)
                .collect::<Vec<_>>()
        );
        Ok(parts
            .iter()
            .flat_map(|part| &part.packages)
            .map(|p| PackageInfo {
                package_id: p.packageid.map(PackageId),
                change_number: p.change_number,
                kv_data: p.buffer.clone(),
            })
            .collect())
    }

    pub async fn get_depot_decryption_key(
        &self,
        depot_id: DepotId,
        app_id: AppId,
    ) -> Result<DepotKey, Error> {
        let req = generated::CMsgClientGetDepotDecryptionKey {
            depot_id: Some(depot_id.0),
            app_id: Some(app_id.0),
        };
        let incoming = self
            .request(
                EMsg::CLIENT_GET_DEPOT_DECRYPTION_KEY,
                &req.encode_to_vec(),
                EMsg::CLIENT_GET_DEPOT_DECRYPTION_KEY_RESPONSE,
            )
            .await?;
        Self::parse_depot_key_response(&incoming.body)
    }

    fn parse_depot_key_response(body: &[u8]) -> Result<DepotKey, Error> {
        let resp = generated::CMsgClientGetDepotDecryptionKeyResponse::decode_checked(body)?;
        let key_data = resp
            .depot_encryption_key
            .ok_or(ConnectionError::MissingField("depot_encryption_key"))?;
        if key_data.len() != 32 {
            return Err(ConnectionError::EncryptionFailed.into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_data);
        Ok(DepotKey(key))
    }

    /// Request access to a private beta branch using a cached password hash.
    /// Returns the depot section KV data on success.
    pub async fn request_private_beta(
        &self,
        app_id: AppId,
        access_token: u64,
        beta_name: &str,
        password_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, Error> {
        let req = generated::CMsgClientPicsPrivateBetaRequest {
            appid: Some(app_id.0),
            access_token: Some(access_token),
            beta_name: Some(beta_name.to_string()),
            password_hash: Some(password_hash.to_vec()),
        };
        let incoming = self
            .request(
                EMsg::CLIENT_PICS_PRIVATE_BETA_REQUEST,
                &req.encode_to_vec(),
                EMsg::CLIENT_PICS_PRIVATE_BETA_RESPONSE,
            )
            .await?;
        Self::parse_private_beta_response(&incoming.body)
    }

    fn parse_private_beta_response(body: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let resp = generated::CMsgClientPicsPrivateBetaResponse::decode_checked(body)?;
        Ok(resp.depot_section)
    }

    pub async fn get_cdn_servers(
        &self,
        cell_id: CellId,
        max_servers: Option<u32>,
    ) -> Result<Vec<CdnServer>, Error> {
        let req = generated::CContentServerDirectoryGetServersForSteamPipeRequest {
            cell_id: Some(cell_id.0),
            max_servers,
            ..Default::default()
        };
        let resp = self
            .call_service_method(
                "ContentServerDirectory.GetServersForSteamPipe#1",
                &req.encode_to_vec(),
            )
            .await?;
        let r: generated::CContentServerDirectoryGetServersForSteamPipeResponse = resp.decode()?;
        Ok(r.servers
            .iter()
            .filter_map(|s| {
                let host_str = s.host.as_deref()?;
                let https = s.https_support.as_deref() == Some("mandatory")
                    || s.https_support.as_deref() == Some("optional");
                let (host, port) = if let Some((h, p)) = host_str.rsplit_once(':') {
                    (
                        h.to_string(),
                        p.parse().unwrap_or(if https { 443 } else { 80 }),
                    )
                } else {
                    (host_str.to_string(), if https { 443 } else { 80 })
                };
                Some(CdnServer {
                    host,
                    port,
                    https,
                    vhost: s.vhost.clone().unwrap_or_default(),
                })
            })
            .collect())
    }

    pub async fn get_manifest_request_code(
        &self,
        app_id: AppId,
        depot_id: DepotId,
        manifest_id: ManifestId,
        branch: Option<&str>,
        branch_password_hash: Option<&str>,
    ) -> Result<Option<u64>, Error> {
        let req = generated::CContentServerDirectoryGetManifestRequestCodeRequest {
            app_id: Some(app_id.0),
            depot_id: Some(depot_id.0),
            manifest_id: Some(manifest_id.0),
            app_branch: branch.map(|s| s.to_string()),
            branch_password_hash: branch_password_hash.map(|s| s.to_string()),
        };
        let resp = self
            .call_service_method(
                "ContentServerDirectory.GetManifestRequestCode#1",
                &req.encode_to_vec(),
            )
            .await?;
        let r: generated::CContentServerDirectoryGetManifestRequestCodeResponse = resp.decode()?;
        Ok(r.manifest_request_code)
    }

    pub async fn get_cdn_auth_token(
        &self,
        app_id: AppId,
        depot_id: DepotId,
        host_name: &str,
    ) -> Result<CdnAuthToken, Error> {
        let req = generated::CContentServerDirectoryGetCdnAuthTokenRequest {
            depot_id: Some(depot_id.0),
            host_name: Some(host_name.to_string()),
            app_id: Some(app_id.0),
        };
        let resp = self
            .call_service_method(
                "ContentServerDirectory.GetCDNAuthToken#1",
                &req.encode_to_vec(),
            )
            .await?;
        let r: generated::CContentServerDirectoryGetCdnAuthTokenResponse = resp.decode()?;
        Ok(CdnAuthToken {
            token: r.token,
            expiration_time: r.expiration_time,
        })
    }
}

impl IncomingMsg {
    /// Parse one decrypted, unframed message (not a `MULTI` batch's body).
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        parse_incoming(data)
    }
}

fn parse_incoming(data: &[u8]) -> Result<IncomingMsg, Error> {
    let parsed = header::PacketHeader::parse(data)?;
    match parsed {
        PacketHeader::Protobuf { header: h, body } => Ok(IncomingMsg {
            emsg: h.emsg,
            is_protobuf: true,
            header: h.decode_header()?,
            body,
        }),
        // The job ids of the non-protobuf headers are carried over so their
        // responses route like protobuf ones.
        PacketHeader::Simple { header: h, body } => Ok(IncomingMsg {
            emsg: h.emsg,
            is_protobuf: false,
            header: generated::CMsgProtoBufHeader {
                jobid_target: Some(h.target_job_id),
                jobid_source: Some(h.source_job_id),
                ..Default::default()
            },
            body,
        }),
        PacketHeader::Extended { header: h, body } => Ok(IncomingMsg {
            emsg: h.emsg,
            is_protobuf: false,
            header: generated::CMsgProtoBufHeader {
                steamid: Some(h.steam_id),
                client_sessionid: Some(h.session_id),
                jobid_target: Some(h.target_job_id),
                jobid_source: Some(h.source_job_id),
                ..Default::default()
            },
            body,
        }),
    }
}

fn check_service_eresult(msg: &IncomingMsg) -> Result<(), Error> {
    if let Some(code) = msg.header.eresult {
        crate::enums::eresult(code).map_err(ConnectionError::ServiceMethodFailed)?;
    }
    Ok(())
}

/// Trait for protobuf response messages that contain an `eresult` field.
/// Implement this for any response proto where the eresult must be checked.
///
/// The default [`decode_checked`](HasEResult::decode_checked) maps non-OK
/// eresults to [`ConnectionError::ServiceMethodFailed`]. Override it for
/// messages that need a more specific error (e.g. `DepotAccessDenied`).
pub trait HasEResult: prost::Message + Default {
    fn get_eresult(&self) -> Option<i32>;

    fn decode_checked(buf: &[u8]) -> Result<Self, Error> {
        let msg = Self::decode(buf)?;
        let code = msg
            .get_eresult()
            .ok_or(ConnectionError::MissingField("eresult"))?;
        crate::enums::eresult(code).map_err(ConnectionError::ServiceMethodFailed)?;
        Ok(msg)
    }
}

impl HasEResult for generated::CMsgClientLogonResponse {
    fn get_eresult(&self) -> Option<i32> {
        self.eresult
    }

    fn decode_checked(buf: &[u8]) -> Result<Self, Error> {
        let msg = Self::decode(buf)?;
        let code = msg
            .get_eresult()
            .ok_or(ConnectionError::MissingField("eresult"))?;
        crate::enums::eresult(code).map_err(ConnectionError::LogonFailed)?;
        Ok(msg)
    }
}

impl HasEResult for generated::CMsgClientGetDepotDecryptionKeyResponse {
    fn get_eresult(&self) -> Option<i32> {
        self.eresult
    }

    fn decode_checked(buf: &[u8]) -> Result<Self, Error> {
        let msg = Self::decode(buf)?;
        let code = msg
            .get_eresult()
            .ok_or(ConnectionError::MissingField("eresult"))?;
        let depot_id = msg.depot_id.unwrap_or(0);
        crate::enums::eresult(code).map_err(|_| ConnectionError::DepotAccessDenied(depot_id))?;
        Ok(msg)
    }
}

impl HasEResult for generated::CMsgClientCheckAppBetaPasswordResponse {
    fn get_eresult(&self) -> Option<i32> {
        self.eresult
    }
}

impl HasEResult for generated::CMsgClientPicsPrivateBetaResponse {
    fn get_eresult(&self) -> Option<i32> {
        self.eresult
    }
}

fn guard_type_from_proto(confirmation_type: Option<i32>) -> Option<GuardType> {
    // A confirmation entry with no type is meaningless and dropped; a present
    // but unrecognized type is retained as GuardType::Unknown.
    Some(GuardType::from_proto(confirmation_type?))
}

#[cfg(test)]
mod tests;
