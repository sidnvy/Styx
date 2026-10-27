# Native App login startup

Implementation slice; native registration, signed package and actual login
acceptance remain separate gates. This preference starts the user's App at
login. It does not install a persistent Host/Gateway service or change role
manager/run/autostart intent.

The original native App is a local OS adapter over its existing owned JSONL
Core pipe. It observes its own installed application and current OS registration;
Rust validates the original App scope and issues a single-use ticket before
an explicit change. These operations are not exposed by Gateway/MCP. Supplied
observations cannot create remote, service, cross-user or execution authority.

- `appLifecycle {observation}` projects the actual OS observation plus Core's
  `observed | pending | unknown` login operation state.
- `appLogin {authorize:true,enabled,observation}` requires a current original
  scope, ordinary admission, supported local platform, a bound observation and
  no pending/unknown login operation. Foreign or unknown registration is refused.
  The result contains one `ticketId` and the requested `enabled` value.
- The original App reobserves and compares the complete fingerprint, then invokes
  at most one native registration/removal. It never replaces a foreign entry.
- `appLoginResult {ticketId,outcome,observation}` consumes only that original
  ticket. Wrong/replayed tickets and success inconsistent with the requested
  direction are refused. Lost replies are not resent. A completed unknown result
  blocks further login changes in that Core; readback does not clear it.

The OS registration is the persistent preference. There is no new Styx preference
file, second transaction ledger, implicit retry, or rewrite of role C07 state.
A new App session observes OS facts and does not replay a prior change. Normal
Quit refuses a still-pending login operation. Completed OS-result uncertainty
alone does not mean a Host executor is active or prevent its normal settlement.

macOS uses `SMAppService.mainApp` for the original installed signed bundle.
`requires_approval` is displayed separately from enabled; the App does not approve
its own entry in System Settings. Windows uses only the current user's exact
Startup shortcut, bound to the current App, arguments, working directory and
state scope. `registered_unverified` never means Windows permits the entry;
StartupApproved is neither parsed nor modified. External changes are reobserved,
not overwritten. Actual login, existing-install updates and uninstall retention
must be verified against final signed packages.
