//! One-shot admission for an OS-owned login preference. The parent native App
//! observes/applies its platform API; only this original Core issues tickets.
//! No role autostart, second preference database, or OS success is inferred here.
use super::{AppError, HostApp, decode_input};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    schema: u16,
    platform: String,
    status: Status,
    fingerprint: Option<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Enabled,
    Disabled,
    NotRegistered,
    RequiresApproval,
    NotFound,
    RegisteredUnverified,
    Foreign,
    Unknown,
}
impl Observation {
    fn validate(&self, platform: &str) -> Result<(), AppError> {
        if self.schema != 1
            || !matches!(platform, "macos" | "windows")
            || self.platform != platform
            || self.fingerprint.as_ref().is_some_and(|v| {
                v.len() != 64
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(AppError("app_login_observation_invalid"));
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadInput {
    observation: Observation,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginInput {
    authorize: bool,
    enabled: bool,
    observation: Observation,
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Succeeded,
    Failed,
    Unknown,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ResultInput {
    ticket_id: String,
    outcome: Outcome,
    observation: Observation,
}
struct Pending {
    ticket: String,
    enabled: bool,
}
#[derive(Default)]
pub(super) struct Login {
    pending: Option<Pending>,
    unknown: bool,
}
impl Login {
    pub(super) fn pending(&self) -> bool {
        self.pending.is_some()
    }
    fn authorize(&mut self, input: LoginInput, platform: &str) -> Result<Value, AppError> {
        input.observation.validate(platform)?;
        if !input.authorize {
            return Err(AppError("app_login_authorization_required"));
        }
        if self.pending.is_some() || self.unknown {
            return Err(AppError("app_login_result_pending"));
        }
        if matches!(input.observation.status, Status::Foreign | Status::Unknown)
            || input.observation.fingerprint.is_none()
            || (input.enabled && input.observation.status == Status::NotFound)
        {
            return Err(AppError("app_login_observation_refused"));
        }
        let ticket = uuid::Uuid::new_v4().simple().to_string();
        self.pending = Some(Pending {
            ticket: ticket.clone(),
            enabled: input.enabled,
        });
        Ok(json!({"login":{"status":"authorized","ticketId":ticket,"enabled":input.enabled}}))
    }
    fn complete(&mut self, input: ResultInput, platform: &str) -> Result<Value, AppError> {
        input.observation.validate(platform)?;
        let pending = self
            .pending
            .as_ref()
            .filter(|p| p.ticket == input.ticket_id)
            .ok_or(AppError("app_login_original_ticket_required"))?;
        // OS approval remains an independent fact. requires_approval and a
        // Windows shortcut do not prove effective login startup.
        if matches!(input.outcome, Outcome::Succeeded)
            && if pending.enabled {
                !matches!(
                    input.observation.status,
                    Status::Enabled | Status::RequiresApproval | Status::RegisteredUnverified
                )
            } else {
                !matches!(
                    input.observation.status,
                    Status::NotRegistered | Status::Disabled
                )
            }
        {
            return Err(AppError("app_login_result_invalid"));
        }
        self.pending = None;
        self.unknown = matches!(input.outcome, Outcome::Unknown);
        Ok(json!({"lifecycle":input.observation,"login":{"status":input.outcome}}))
    }
    fn observe(&self, input: ReadInput, platform: &str) -> Result<Value, AppError> {
        input.observation.validate(platform)?;
        Ok(
            json!({"lifecycle":input.observation,"login":{"status":if self.pending.is_some() {
            "pending"
        } else if self.unknown { "unknown" } else { "observed" }}}),
        )
    }
}
impl HostApp {
    pub(super) fn login_read(
        &self,
        input: Box<serde_json::value::RawValue>,
    ) -> Result<Value, AppError> {
        self.scope.validate()?;
        self.login
            .observe(decode_input(&input)?, std::env::consts::OS)
    }
    pub(super) fn login_authorize(
        &mut self,
        input: Box<serde_json::value::RawValue>,
    ) -> Result<Value, AppError> {
        self.available()?;
        self.login
            .authorize(decode_input(&input)?, std::env::consts::OS)
    }
    pub(super) fn login_complete(
        &mut self,
        input: Box<serde_json::value::RawValue>,
    ) -> Result<Value, AppError> {
        // Consume only the original ticket, even if another capability becomes
        // fenced while the already-authorized native API is completing.
        self.scope.validate()?;
        self.login
            .complete(decode_input(&input)?, std::env::consts::OS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation(status: Status) -> Observation {
        Observation {
            schema: 1,
            platform: "windows".into(),
            status,
            fingerprint: Some("a".repeat(64)),
        }
    }
    fn request(enabled: bool, status: Status) -> LoginInput {
        LoginInput {
            authorize: true,
            enabled,
            observation: observation(status),
        }
    }
    #[test]
    fn login_ticket_cannot_be_replaced_replayed_or_claim_effective_startup() {
        let mut login = Login::default();
        assert!(
            login
                .authorize(request(true, Status::Foreign), "windows")
                .is_err()
        );
        assert!(
            login
                .authorize(request(true, Status::Unknown), "windows")
                .is_err()
        );
        let result = login
            .authorize(request(true, Status::NotRegistered), "windows")
            .unwrap();
        let ticket = result["login"]["ticketId"].as_str().unwrap().to_owned();
        assert!(
            login
                .authorize(request(false, Status::NotRegistered), "windows")
                .is_err()
        );
        assert!(
            login
                .complete(
                    ResultInput {
                        ticket_id: "b".repeat(32),
                        outcome: Outcome::Succeeded,
                        observation: observation(Status::RegisteredUnverified)
                    },
                    "windows"
                )
                .is_err()
        );
        assert!(login.pending());
        assert!(
            login
                .complete(
                    ResultInput {
                        ticket_id: ticket.clone(),
                        outcome: Outcome::Succeeded,
                        observation: observation(Status::NotRegistered)
                    },
                    "windows"
                )
                .is_err()
        );
        let result = login
            .complete(
                ResultInput {
                    ticket_id: ticket.clone(),
                    outcome: Outcome::Succeeded,
                    observation: observation(Status::RegisteredUnverified),
                },
                "windows",
            )
            .unwrap();
        assert_eq!(result["lifecycle"]["status"], "registered_unverified");
        assert!(
            login
                .complete(
                    ResultInput {
                        ticket_id: ticket,
                        outcome: Outcome::Succeeded,
                        observation: observation(Status::RegisteredUnverified)
                    },
                    "windows"
                )
                .is_err()
        );
        let result = login
            .authorize(request(false, Status::RegisteredUnverified), "windows")
            .unwrap();
        login
            .complete(
                ResultInput {
                    ticket_id: result["login"]["ticketId"].as_str().unwrap().into(),
                    outcome: Outcome::Unknown,
                    observation: observation(Status::Unknown),
                },
                "windows",
            )
            .unwrap();
        assert!(
            login
                .authorize(request(false, Status::RegisteredUnverified), "windows")
                .is_err()
        );
        let view = login
            .observe(
                ReadInput {
                    observation: observation(Status::NotRegistered),
                },
                "windows",
            )
            .unwrap();
        assert_eq!(view["login"]["status"], "unknown");
        assert!(
            login
                .authorize(request(false, Status::NotRegistered), "windows")
                .is_err()
        );
    }
    #[test]
    fn login_rejects_wrong_platform_authorization_and_unbound_absence() {
        let mut login = Login::default();
        assert!(
            login
                .authorize(request(true, Status::NotRegistered), "macos")
                .is_err()
        );
        assert!(
            login
                .authorize(request(true, Status::NotRegistered), "linux")
                .is_err()
        );
        let mut input = request(true, Status::NotRegistered);
        input.authorize = false;
        assert!(login.authorize(input, "windows").is_err());
        let mut input = request(true, Status::NotRegistered);
        input.observation.fingerprint = None;
        assert!(login.authorize(input, "windows").is_err());
    }
}
