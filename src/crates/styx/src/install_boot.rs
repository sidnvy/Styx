//! Linux Gateway boot behavior through the existing user's systemd manager.
//! The installer calls this before starting a Gateway; no accounts are created.
use super::{setup::Failure, setup_prompt as prompt};
use std::process::Command;

type Result<T> = std::result::Result<T, Failure>;

fn parse_linger(output: &[u8]) -> Result<bool> {
    match std::str::from_utf8(output).map(str::trim) {
        Ok("yes") => Ok(true),
        Ok("no") => Ok(false),
        _ => Err(Failure::new("install_gateway_boot_state_invalid")),
    }
}

fn read_linger(uid: &str) -> Result<bool> {
    let output = Command::new("loginctl")
        .args(["show-user", uid, "--property=Linger", "--value"])
        .output()
        .map_err(|_| Failure::new("install_gateway_boot_state_unavailable"))?;
    if !output.status.success() {
        return Err(Failure::new("install_gateway_boot_state_unavailable"));
    }
    parse_linger(&output.stdout)
}

fn enable_linger(uid: &str) -> Result<()> {
    // Inherit the terminal so the OS can present its own authorization prompt.
    // Never invoke sudo or repeat this mutation after a missing/failed result.
    let mut child = Command::new("loginctl")
        .args(["enable-linger", uid])
        .spawn()
        .map_err(|_| Failure::new("install_gateway_boot_enable_not_started"))?;
    let status = child
        .wait()
        .map_err(|_| Failure::unknown("install_gateway_boot_enable_unknown"))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::new("install_gateway_boot_enable_failed"))
    }
}

fn ensure(
    mut read: impl FnMut() -> Result<bool>,
    confirm: impl FnOnce() -> Result<bool>,
    enable: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if read()? {
        return Ok(());
    }
    if !confirm()? {
        return Err(Failure::new("install_gateway_boot_cancelled"));
    }
    let result = enable();
    // This independent observation is also made after an enable failure. A
    // failure remains a failure; neither a lost result nor a no reply is retried.
    let observed = read();
    result?;
    match observed {
        Ok(true) => Ok(()),
        Ok(false) => Err(Failure::new("install_gateway_boot_not_enabled")),
        Err(_) => Err(Failure::unknown(
            "install_gateway_boot_verification_unknown",
        )),
    }
}

pub(super) fn ensure_gateway_boot() -> Result<()> {
    let uid = nix::unistd::geteuid().as_raw().to_string();
    let result = ensure(
        || read_linger(&uid),
        || {
            prompt::info(
                "To keep this Gateway available before login and after logout, Linux needs to keep this account's user service manager running. This applies to all enabled user services for this account, including Styx.",
            );
            if !prompt::terminal() {
                prompt::info(
                    "Run this setup in a terminal to review the change, or ask an administrator to enable lingering for this account first. This setup has not started the Gateway.",
                );
                return Err(Failure::new("install_gateway_boot_confirmation_required"));
            }
            prompt::info("Linux may ask you to authorize this change.");
            prompt::confirm("Allow this account's services to run at boot and after logout?")
                .map_err(Failure::new)
        },
        || enable_linger(&uid),
    );
    if let Err(error) = &result {
        if error.code == "install_gateway_boot_cancelled" {
            prompt::info(
                "Gateway setup was cancelled. Installed Styx files are kept; this setup did not start the Gateway.",
            );
        } else if error.code != "install_gateway_boot_confirmation_required" {
            prompt::info(
                "Styx could not confirm background startup for this account. This setup has not started the Gateway. Check the account's lingering setting with your administrator; this setup will not repeat the change automatically.",
            );
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn only_explicit_linger_property_values_are_accepted() {
        assert!(parse_linger(b"yes\n").unwrap());
        assert!(!parse_linger(b"no\n").unwrap());
        for output in [
            b"".as_slice(),
            b"Linger=yes\n",
            b"yes\nno\n",
            b"true",
            b"\xff",
        ] {
            assert_eq!(
                parse_linger(output).unwrap_err().code,
                "install_gateway_boot_state_invalid"
            );
        }
    }

    #[test]
    fn existing_boot_setting_does_not_prompt_or_mutate() {
        ensure(
            || Ok(true),
            || panic!("already configured account must not prompt"),
            || panic!("already configured account must not mutate"),
        )
        .unwrap();
    }

    #[test]
    fn declining_boot_change_does_not_enable_services() {
        assert_eq!(
            ensure(|| Ok(false), || Ok(false), || panic!("declined mutation"))
                .unwrap_err()
                .code,
            "install_gateway_boot_cancelled"
        );
    }

    #[test]
    fn command_success_requires_independent_enabled_observation() {
        for (after, expected) in [
            (true, None),
            (false, Some("install_gateway_boot_not_enabled")),
        ] {
            let reads = Cell::new(0);
            let writes = Cell::new(0);
            let result = ensure(
                || {
                    reads.set(reads.get() + 1);
                    Ok(reads.get() > 1 && after)
                },
                || Ok(true),
                || {
                    writes.set(writes.get() + 1);
                    Ok(())
                },
            );
            assert_eq!(result.err().map(|error| error.code), expected);
            assert_eq!(reads.get(), 2);
            assert_eq!(writes.get(), 1);
        }
    }

    #[test]
    fn failed_or_unknown_enable_is_observed_but_never_replayed_or_reported_success() {
        for unknown in [false, true] {
            let reads = Cell::new(0);
            let writes = Cell::new(0);
            let failure = ensure(
                || {
                    reads.set(reads.get() + 1);
                    Ok(reads.get() > 1)
                },
                || Ok(true),
                || {
                    writes.set(writes.get() + 1);
                    Err(if unknown {
                        Failure::unknown("original_enable_unknown")
                    } else {
                        Failure::new("original_enable_failed")
                    })
                },
            )
            .unwrap_err();
            assert_eq!(failure.exit, if unknown { 4 } else { 2 });
            assert_eq!(reads.get(), 2);
            assert_eq!(writes.get(), 1);
        }
    }

    #[test]
    fn lost_verification_is_unknown_without_another_mutation() {
        let reads = Cell::new(0);
        let writes = Cell::new(0);
        let failure = ensure(
            || {
                reads.set(reads.get() + 1);
                if reads.get() == 1 {
                    Ok(false)
                } else {
                    Err(Failure::new("read_failed"))
                }
            },
            || Ok(true),
            || {
                writes.set(writes.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(failure.code, "install_gateway_boot_verification_unknown");
        assert_eq!(failure.exit, 4);
        assert_eq!(writes.get(), 1);
    }
}
