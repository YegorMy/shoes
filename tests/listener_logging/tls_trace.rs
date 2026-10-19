//! Independent tracing capture, including native dependency events and span fields.
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};
use tracing_core::span::Current;

use super::{FIXTURE_CLIENT, guard};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TraceRecord {
    kind: String,
    fixture_client: bool,
    level: String,
    target: String,
    name: String,
    span: Option<u64>,
    related_span: Option<u64>,
    fields: Vec<(String, String)>,
}

#[derive(Default)]
struct Fields(Vec<(String, String)>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().into(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().into(), value.into()));
    }
}

struct Collector {
    file: Mutex<File>,
    next_span: AtomicU64,
    spans: Mutex<BTreeMap<u64, (&'static Metadata<'static>, usize)>>,
    entered: Mutex<HashMap<std::thread::ThreadId, Vec<u64>>>,
}

impl Collector {
    fn current(&self) -> Option<u64> {
        self.entered
            .lock()
            .get(&std::thread::current().id())
            .and_then(|spans| spans.last().copied())
    }

    fn write(
        &self,
        kind: &str,
        metadata: &Metadata<'_>,
        span: Option<u64>,
        related_span: Option<u64>,
        fields: Fields,
    ) {
        let record = TraceRecord {
            kind: kind.into(),
            fixture_client: FIXTURE_CLIENT.try_with(|_| ()).is_ok(),
            level: metadata.level().to_string(),
            target: metadata.target().into(),
            name: metadata.name().into(),
            span,
            related_span,
            fields: fields.0,
        };
        let mut file = self.file.lock();
        serde_json::to_writer(&mut *file, &record).unwrap();
        file.write_all(b"\n").unwrap();
    }

    fn span_record(&self, kind: &str, span: &Id, related: Option<u64>, fields: Fields) {
        let metadata = self.spans.lock()[&span.into_u64()].0;
        self.write(kind, metadata, Some(span.into_u64()), related, fields);
    }
}

impl Subscriber for Collector {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = self.next_span.fetch_add(1, Ordering::SeqCst);
        self.spans.lock().insert(id, (attributes.metadata(), 1));
        let mut fields = Fields::default();
        attributes.record(&mut fields);
        let parent = attributes
            .parent()
            .map(Id::into_u64)
            .or_else(|| attributes.is_contextual().then(|| self.current()).flatten());
        self.write("span_open", attributes.metadata(), Some(id), parent, fields);
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut fields = Fields::default();
        values.record(&mut fields);
        self.span_record("span_fields", span, None, fields);
    }

    fn record_follows_from(&self, span: &Id, follows: &Id) {
        self.span_record(
            "span_follows",
            span,
            Some(follows.into_u64()),
            Fields::default(),
        );
    }

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.write(
            "event",
            event.metadata(),
            event
                .parent()
                .map(Id::into_u64)
                .or_else(|| event.is_contextual().then(|| self.current()).flatten()),
            None,
            fields,
        );
    }

    fn enter(&self, span: &Id) {
        self.entered
            .lock()
            .entry(std::thread::current().id())
            .or_default()
            .push(span.into_u64());
        self.span_record("span_enter", span, None, Fields::default());
    }

    fn exit(&self, span: &Id) {
        self.span_record("span_exit", span, None, Fields::default());
        let mut entered = self.entered.lock();
        let thread = std::thread::current().id();
        let spans = entered.get_mut(&thread).unwrap();
        let index = spans.iter().rposition(|id| *id == span.into_u64()).unwrap();
        spans.remove(index);
        if spans.is_empty() {
            entered.remove(&thread);
        }
    }

    fn clone_span(&self, span: &Id) -> Id {
        self.spans.lock().get_mut(&span.into_u64()).unwrap().1 += 1;
        span.clone()
    }

    fn current_span(&self) -> Current {
        match self.current() {
            Some(id) => Current::new(Id::from_u64(id), self.spans.lock()[&id].0),
            None => Current::none(),
        }
    }

    fn try_close(&self, span: Id) -> bool {
        let mut spans = self.spans.lock();
        let (metadata, references) = spans.get_mut(&span.into_u64()).unwrap();
        *references -= 1;
        if *references != 0 {
            return false;
        }
        self.write(
            "span_close",
            metadata,
            Some(span.into_u64()),
            None,
            Fields::default(),
        );
        spans.remove(&span.into_u64());
        true
    }
}

pub(super) fn install(dir: &Path) {
    tracing::subscriber::set_global_default(collector(dir))
        .expect("tracing subscriber must be independently live across spawned tasks");
}

fn collector(dir: &Path) -> Collector {
    Collector {
        file: Mutex::new(File::create(dir.join("tracing.jsonl")).unwrap()),
        next_span: AtomicU64::new(1),
        spans: Mutex::new(BTreeMap::new()),
        entered: Mutex::new(HashMap::new()),
    }
}

// Forward complete facade records in addition to native tracing instrumentation.
// Both original log channels remain independently captured and checked.
pub(super) fn bridge(record: &log::Record<'_>) {
    macro_rules! forward {
        ($level:expr) => {{
            tracing::event!(target: "tls_privacy_engine_log", $level,
                log_level = record.level().as_str(), log_target = record.target(),
                message = %record.args());
        }};
    }
    match record.level() {
        log::Level::Error => forward!(tracing::Level::ERROR),
        log::Level::Warn => forward!(tracing::Level::WARN),
        log::Level::Info => forward!(tracing::Level::INFO),
        log::Level::Debug => forward!(tracing::Level::DEBUG),
        log::Level::Trace => forward!(tracing::Level::TRACE),
    }
}

fn original(record: &TraceRecord) -> Result<guard::Event, &'static str> {
    if record.kind != "event" || record.span.is_some() || record.related_span.is_some() {
        return Err("unclassified tracing context or span fields");
    }
    let field = |name: &str| {
        let mut values = record.fields.iter().filter(|(key, _)| key == name);
        match (values.next(), values.next()) {
            (Some((_, value)), None) => Ok(value.clone()),
            _ => Err("missing or repeated tracing field"),
        }
    };
    let target = match record.target.as_str() {
        "tls_privacy_engine_log" if record.fields.len() == 3 => {
            if field("log_level")? != record.level {
                return Err("incorrect bridged event level");
            }
            field("log_target")?
        }
        "tls_privacy_control" if record.fields.len() == 1 => record.target.clone(),
        _ => return Err("unclassified tracing target or extra fields"),
    };
    Ok(guard::Event {
        fixture_client: record.fixture_client,
        level: record.level.clone(),
        target,
        message: field("message")?,
        formatted: String::new(),
    })
}

fn private(record: &TraceRecord, protected: &[String]) -> Result<(), &'static str> {
    let original = original(record)?;
    if original.fixture_client {
        return guard::fixture_record(&original);
    }
    let metadata = format!("{} {}", record.kind, record.name);
    if metadata.contains(['\r', '\n']) || protected.iter().any(|s| metadata.contains(s)) {
        return Err("protected tracing metadata");
    }
    guard::server_record(&original, protected)
}

pub(super) fn inspect(dir: &Path, protected: &[String], logs: &[guard::Event]) {
    let bytes = std::fs::read(dir.join("tracing.jsonl")).unwrap();
    assert!(bytes.ends_with(b"\n"), "incomplete tracing capture");
    let records: Vec<TraceRecord> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for record in &records {
        assert!(
            private(record, protected).is_ok(),
            "unsafe tracing record: {record:?}"
        );
    }
    let forwarded: Vec<_> = records
        .iter()
        .filter(|record| record.target == "tls_privacy_engine_log")
        .map(|record| original(record).unwrap())
        .collect();
    assert_eq!(
        forwarded.len(),
        logs.len(),
        "every original log must reach tracing"
    );
    for (forwarded, log) in forwarded.iter().zip(logs) {
        assert_eq!(
            (
                &forwarded.level,
                &forwarded.target,
                &forwarded.message,
                forwarded.fixture_client
            ),
            (&log.level, &log.target, &log.message, log.fixture_client)
        );
    }
    for (level, message) in [
        ("DEBUG", "debug collector active"),
        ("TRACE", "trace collector active"),
    ] {
        assert!(
            records
                .iter()
                .any(|record| record.target == "tls_privacy_control"
                    && record.level == level
                    && record.fields == [("message".into(), message.into())]),
            "native tracing control must arrive from a spawned task"
        );
    }
}

#[test]
fn tracing_guard_rejects_extra_fields_spans_and_wrong_contexts() {
    let mut record = TraceRecord {
        kind: "event".into(),
        fixture_client: false,
        level: "DEBUG".into(),
        target: "tls_privacy_control".into(),
        name: "event control".into(),
        span: None,
        related_span: None,
        fields: vec![("message".into(), "debug collector active".into())],
    };
    assert!(private(&record, &[]).is_ok());
    for value in [
        "ClientHelloPayload {\n server_name: private.invalid\n}",
        "NewSessionTicketPayloadTls13 {\n nonce: aa, ticket: bb\n}",
        "peer=192.0.2.171:49171",
        "Starting ShadowTLSv3 TCP server at 127.0.0.1:41973",
    ] {
        record.fields.push(("extra".into(), value.into()));
        assert!(private(&record, &[]).is_err());
        record.fields.pop();
        record.fields[0].1 = value.into();
        assert!(private(&record, &[]).is_err());
        record.fields[0].1 = "debug collector active".into();
    }
    record
        .fields
        .push(("message".into(), "debug collector active".into()));
    assert!(private(&record, &[]).is_err());
    record.fields.pop();
    record.kind = "span_fields".into();
    assert!(private(&record, &[]).is_err());
    record.kind = "event".into();
    record.span = Some(1);
    assert!(private(&record, &[]).is_err());
    record.span = None;
    record.target = "unexpected::dependency".into();
    assert!(private(&record, &[]).is_err());
    record.fixture_client = true;
    assert!(private(&record, &[]).is_err());
    record.target = "tls_privacy_engine_log".into();
    record.fields.extend([
        ("log_level".into(), "DEBUG".into()),
        ("log_target".into(), "rustls::server::hs".into()),
    ]);
    assert!(
        private(&record, &[]).is_err(),
        "server cannot become fixture output"
    );
}

#[test]
fn tracing_collector_preserves_injected_event_and_span_fields() {
    let root = std::env::var_os("SHOES_TLS_PRIVACY_CAPTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&root).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("tracing-control-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    println!("Complete injected tracing control capture: {}", dir.display());
    let payload = "Finished {\n verify_data: tracing-payload-canary\n}";
    tracing::subscriber::with_default(collector(&dir), || {
        let assert_no_current = || {
            assert!(tracing::Span::current().is_none());
            tracing::dispatcher::get_default(|dispatch| {
                let current = dispatch.current_span();
                assert!(current.is_known());
                assert!(current.id().is_none());
                assert!(current.metadata().is_none());
            });
        };
        assert_no_current();
        let span = tracing::debug_span!(target: "tls_privacy_control", "injected span",
            sni = "tracing-sni.private.invalid", credential = tracing::field::Empty);
        span.record("credential", "tracing-credential-canary");
        assert_no_current();
        let retained_current = {
            let _entered = span.enter();
            let current = tracing::Span::current();
            assert_eq!(current.id(), span.id());
            assert!(std::ptr::eq(
                current.metadata().unwrap(),
                span.metadata().unwrap()
            ));
            current.record("credential", "tracing-current-credential-canary");
            {
                let child = tracing::debug_span!(target: "tls_privacy_control", "injected child",
                    credential = tracing::field::Empty);
                assert_eq!(tracing::Span::current().id(), span.id());
                let _child_entered = child.enter();
                let child_current = tracing::Span::current();
                assert_eq!(child_current.id(), child.id());
                assert!(std::ptr::eq(
                    child_current.metadata().unwrap(),
                    child.metadata().unwrap()
                ));
                child_current.record("credential", "tracing-nested-credential-canary");
                tracing::debug!(target: "tls_privacy_control", peer = "192.0.2.171:49171",
                    extra = payload, "debug collector active");
            }
            assert_eq!(tracing::Span::current().id(), span.id());
            tracing::Span::current().record("credential", "tracing-restored-credential-canary");
            current
        };
        assert_no_current();
        drop(span);
        retained_current.record("credential", "tracing-retained-credential-canary");
        drop(retained_current);
        assert_no_current();
    });
    let raw = std::fs::read_to_string(dir.join("tracing.jsonl")).unwrap();
    assert!(raw.ends_with('\n'), "incomplete tracing control capture");
    let records: Vec<TraceRecord> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for value in [
        payload,
        "tracing-sni.private.invalid",
        "tracing-credential-canary",
        "tracing-current-credential-canary",
        "tracing-nested-credential-canary",
        "tracing-restored-credential-canary",
        "tracing-retained-credential-canary",
        "192.0.2.171:49171",
    ] {
        assert!(
            records
                .iter()
                .any(|record| record.fields.iter().any(|(_, captured)| captured == value)),
            "collector lost {value:?}"
        );
    }
    for record in &records {
        assert!(
            private(record, &[]).is_err(),
            "injected context admitted: {record:?}"
        );
    }
    assert!(records.iter().any(|record| record.kind == "span_close"));
    let parent = records
        .iter()
        .find(|record| record.name == "injected span" && record.kind == "span_open")
        .unwrap();
    let child = records
        .iter()
        .find(|record| record.name == "injected child" && record.kind == "span_open")
        .unwrap();
    assert_eq!(
        child.related_span, parent.span,
        "implicit span ancestry must be retained"
    );
    for (value, span) in [
        ("tracing-credential-canary", parent.span),
        ("tracing-current-credential-canary", parent.span),
        ("tracing-nested-credential-canary", child.span),
        ("tracing-restored-credential-canary", parent.span),
        ("tracing-retained-credential-canary", parent.span),
    ] {
        let field = records
            .iter()
            .position(|record| {
                record.kind == "span_fields"
                    && record.span == span
                    && record.fields == [("credential".into(), value.into())]
            })
            .unwrap();
        let closes: Vec<_> = records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.kind == "span_close" && record.span == span)
            .collect();
        assert_eq!(closes.len(), 1, "span must close only after its last handle");
        assert!(field < closes[0].0, "field must precede span closure");
    }
    assert!(
        records
            .iter()
            .any(|record| record.kind == "event" && record.span == child.span),
        "implicit event context must be retained"
    );
}
