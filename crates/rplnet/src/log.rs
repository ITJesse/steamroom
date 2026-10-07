//! Forwards `tracing` events from rplnet and steamroom to a sink the app
//! implements, so they end up in the app's own log. Messages are redacted
//! before they leave Rust: URL queries (CDN auth tokens travel there) and
//! JWTs (Steam access and refresh tokens) are replaced.

use std::fmt::Write;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use tracing::Event;
use tracing::Metadata;
use tracing::Subscriber;
use tracing::field::Field;
use tracing::field::Visit;
use tracing::span;
use tracing::subscriber::Interest;

/// Severity, from least to most verbose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum RplnetLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl RplnetLogLevel {
    fn from_tracing(level: &tracing::Level) -> Self {
        match *level {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::INFO => Self::Info,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::TRACE => Self::Trace,
        }
    }

    /// 1 (error) to 5 (trace); 0 means nothing is forwarded.
    fn rank(self) -> u8 {
        self as u8 + 1
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetLogRecord {
    pub level: RplnetLogLevel,
    /// Module path of the emitting code, e.g. `steamroom::client::dispatch`.
    pub target: String,
    /// The event's message followed by its fields as `key=value`, redacted.
    pub message: String,
}

/// Implemented by the app. Called synchronously on the thread that emitted
/// the event, so it must not block.
#[uniffi::export(with_foreign)]
pub trait RplnetLogSink: Send + Sync {
    fn log(&self, record: RplnetLogRecord);
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RplnetLogSinkError {
    /// Another `tracing` subscriber was installed as the process default
    /// first, so events cannot be routed to the sink.
    #[error("another tracing subscriber is already the process default")]
    SubscriberAlreadySet,
}

static SINK: RwLock<Option<Arc<dyn RplnetLogSink>>> = RwLock::new(None);
static MAX_RANK: AtomicU8 = AtomicU8::new(0);
static INSTALLED: OnceLock<bool> = OnceLock::new();

/// Route events up to `max_level` to `sink`. Calling it again replaces the
/// sink and the level.
#[uniffi::export]
pub fn rplnet_set_log_sink(
    sink: Arc<dyn RplnetLogSink>,
    max_level: RplnetLogLevel,
) -> Result<(), RplnetLogSinkError> {
    *SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(sink);
    MAX_RANK.store(max_level.rank(), Ordering::Relaxed);
    let installed =
        *INSTALLED.get_or_init(|| tracing::subscriber::set_global_default(Bridge).is_ok());
    if installed {
        Ok(())
    } else {
        Err(RplnetLogSinkError::SubscriberAlreadySet)
    }
}

struct Bridge;

impl Subscriber for Bridge {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        // The level can change at runtime, so ask `enabled` every time.
        Interest::sometimes()
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        RplnetLogLevel::from_tracing(metadata.level()).rank() <= MAX_RANK.load(Ordering::Relaxed)
    }

    // Spans carry no information the app logs; they are accepted and ignored.
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let Some(sink) = SINK
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(Arc::clone)
        else {
            return;
        };
        let mut text = Fields::default();
        event.record(&mut text);
        sink.log(RplnetLogRecord {
            level: RplnetLogLevel::from_tracing(event.metadata().level()),
            target: event.metadata().target().to_string(),
            message: redact(&text.finish()),
        });
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

#[derive(Default)]
struct Fields {
    message: String,
    fields: String,
}

impl Fields {
    fn finish(self) -> String {
        if self.fields.is_empty() {
            self.message
        } else if self.message.is_empty() {
            self.fields.trim_start().to_string()
        } else {
            self.message + &self.fields
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={}", field.name(), value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }
}

/// Remove secrets that may appear in log text and error details: the query
/// of every `http(s)://` URL, and anything shaped like a JWT.
pub fn redact(text: &str) -> String {
    redact_jwts(&redact_url_queries(text))
}

fn is_url_end(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']' | '}' | '`')
}

fn redact_url_queries(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = ["https://", "http://"]
        .iter()
        .filter_map(|scheme| rest.find(scheme))
        .min()
    {
        out.push_str(&rest[..start]);
        let url_and_tail = &rest[start..];
        let end = url_and_tail.find(is_url_end).unwrap_or(url_and_tail.len());
        let url = &url_and_tail[..end];
        match url.find('?') {
            Some(query) => {
                out.push_str(&url[..query]);
                out.push_str("?<redacted>");
            }
            None => out.push_str(url),
        }
        rest = &url_and_tail[end..];
    }
    out.push_str(rest);
    out
}

fn is_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn redact_jwts(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("eyJ") {
        let candidate = &rest[start..];
        let len = candidate
            .find(|c: char| !(is_base64url(c) || c == '.'))
            .unwrap_or(candidate.len());
        let token = &candidate[..len];
        let segments = token.split('.').filter(|s| !s.is_empty()).count();
        out.push_str(&rest[..start]);
        if segments == 3 && token.matches('.').count() == 2 {
            out.push_str("<redacted-token>");
        } else {
            out.push_str(token);
        }
        rest = &candidate[len..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn url_queries_are_removed() {
        assert_eq!(
            redact(
                "error sending request for url (https://cache1-hkg1.steamcontent.com/depot/1/chunk/ab?token=SECRET&x=1)"
            ),
            "error sending request for url (https://cache1-hkg1.steamcontent.com/depot/1/chunk/ab?<redacted>)"
        );
        assert_eq!(
            redact("http://a.example/x?q=1 and https://b.example/y"),
            "http://a.example/x?<redacted> and https://b.example/y"
        );
        assert_eq!(redact("no urls here?"), "no urls here?");
    }

    #[test]
    fn jwts_are_removed() {
        let jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiI3NjU2MTE5In0.c2lnbmF0dXJl-_x";
        assert_eq!(
            redact(&format!("token={jwt}, done")),
            "token=<redacted-token>, done"
        );
        // Not three segments: left alone.
        assert_eq!(redact("eyJhbGciOiJ9 plain"), "eyJhbGciOiJ9 plain");
    }

    struct Capture(Mutex<Vec<RplnetLogRecord>>);

    impl RplnetLogSink for Capture {
        fn log(&self, record: RplnetLogRecord) {
            self.0.lock().unwrap().push(record);
        }
    }

    #[test]
    fn events_reach_the_sink_filtered_and_redacted() {
        let capture = Arc::new(Capture(Mutex::new(Vec::new())));
        rplnet_set_log_sink(capture.clone(), RplnetLogLevel::Info).unwrap();
        tracing::debug!("below the level");
        tracing::warn!(depot = 11, "fetch failed: https://h.example/p?token=abc");
        let records = capture.0.lock().unwrap().clone();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].level, RplnetLogLevel::Warn);
        assert_eq!(
            records[0].message,
            "fetch failed: https://h.example/p?<redacted> depot=11"
        );
        assert!(records[0].target.starts_with("rplnet"));

        // Raising the level takes effect without reinstalling.
        rplnet_set_log_sink(capture.clone(), RplnetLogLevel::Debug).unwrap();
        tracing::debug!("now visible");
        assert_eq!(capture.0.lock().unwrap().len(), 2);
    }
}
