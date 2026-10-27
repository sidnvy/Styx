//! Opt-in stage observations only; never consulted for admission or settlement.
use std::{
    ffi::OsStr,
    io::Write as _,
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Clone)]
pub(crate) struct StartupDiagnostic {
    started: Instant,
    stage: Arc<Mutex<(&'static str, Instant)>>,
}
impl StartupDiagnostic {
    pub(crate) fn from_env() -> Option<Self> {
        (std::env::var_os("STYX_GATEWAY_STARTUP_DIAGNOSTICS").as_deref() == Some(OsStr::new("1")))
            .then(|| {
                let now = Instant::now();
                Self {
                    started: now,
                    stage: Arc::new(Mutex::new(("scheduled", now))),
                }
            })
    }
    pub(crate) fn report(&self, stage: &'static str) {
        let (now, previous, elapsed) = {
            let mut current = self.stage.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let previous = current.0;
            let elapsed = now.duration_since(current.1).as_millis();
            *current = (stage, now);
            (now, previous, elapsed)
        };
        // Only compile-time labels and monotonic durations. Logging failure
        // must not replace a startup, validation or original cleanup result.
        let _ = writeln!(
            std::io::stderr().lock(),
            "{}",
            serde_json::json!({"event":"styx_app_startup","stage":stage,
                "previous_stage":previous,"elapsed_ms":now.duration_since(self.started).as_millis(),
                "stage_elapsed_ms":elapsed})
        );
    }
}
