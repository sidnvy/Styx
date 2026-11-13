use super::{Answers, Failure, Result, Session, admin, inputs, now_ms, prompt, root_default};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};

pub(in crate::cli) async fn invite(root: Option<PathBuf>) -> Result<()> {
    if !prompt::terminal() {
        return Err("invite_interactive_terminal_required".into());
    }
    let root = root.map(Ok).unwrap_or_else(root_default)?;
    let answers = Answers::load(&root.join("inputs/setup-intent.json"))?;
    if !answers.role.owns_gateway() {
        return Err("invite_requires_local_hub".into());
    }
    let session = Session {
        root,
        answers,
        automated: false,
        plan_approved: false,
        mutation: Default::default(),
    };
    let gateway = session.root.join("gateway");
    let observed = admin::observe(&gateway).await.map_err(Failure::admin)?;
    let origins = observed["origins"]
        .as_array()
        .ok_or_else(|| Failure::new("invite_origins_unavailable"))?;
    println!(
        "Choose an origin reachable from the other computer. Loopback is for this computer only; use a selected private network for another computer."
    );
    for (i, origin) in origins.iter().enumerate() {
        println!("{}. {}", i + 1, origin.as_str().unwrap_or("unknown"));
    }
    let index = prompt::line("Origin number", None)?
        .parse::<usize>()
        .map_err(|_| Failure::new("invite_origin_invalid"))?;
    let origin = origins
        .get(
            index
                .checked_sub(1)
                .ok_or_else(|| Failure::new("invite_origin_invalid"))?,
        )
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::new("invite_origin_invalid"))?;
    let selection = if index == 1 {
        admin::InvitationOrigin::Loopback
    } else {
        let address = origin
            .strip_prefix("https://")
            .and_then(|s| s.split(':').next())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Failure::new("invite_origin_invalid"))?;
        admin::InvitationOrigin::Address(address)
    };
    // A prior unknown invitation cannot be evaded by inventing another name.
    for entry in std::fs::read_dir(session.root.join("inputs"))
        .map_err(|_| Failure::new("invite_inputs_unavailable"))?
    {
        let entry = entry.map_err(|_| Failure::new("invite_inputs_unavailable"))?;
        if let Some(name) = entry.file_name().to_str()
            && name.starts_with("invite-export-")
            && let Some(step) = name.strip_suffix(".started")
            && !session.completed(step)
        {
            return Err(Failure::unknown(
                "invite_previous_outcome_unknown_check_original_files",
            ));
        }
    }
    session.consent("invite", "Create a secret one-use invitation, valid for ten minutes, and print its join link in this terminal. Transfer it only through a trusted private channel.")?;
    let step = format!("invite-export-{}", now_ms()?);
    let invitation = session.input(&format!("{step}.token"));
    let link = session.input(&format!("{step}.link"));
    session.begin(&step)?;
    admin::invite_with_options(&gateway, &invitation, 600, Some(selection), Some(&link))
        .await
        .map_err(Failure::admin)?;
    session.done(&step)?;
    let link_bytes = inputs::read_private(&link, 32768)
        .map_err(|_| Failure::unknown("invite_link_publication_unknown"))?;
    println!(
        "{}",
        std::str::from_utf8(&link_bytes)
            .map_err(|_| Failure::unknown("invite_link_publication_unknown"))?
    );
    println!(
        "On the other computer:\nApp: choose Join an existing Styx and paste this link.\nCLI: run styx setup, choose Join an existing hub and paste this link.\nCompare the code shown there with this hub before approving."
    );
    if !prompt::confirm("Wait for a pending request and review approval? Ctrl-C stops waiting")? {
        return Ok(());
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        let pending = admin::pending(&gateway)
            .await
            .map_err(Failure::admin)?
            .pending
            .unwrap_or_default();
        if !pending.is_empty() {
            for (i, p) in pending.iter().enumerate() {
                println!(
                    "{}. Computer {}\n   Request {}\n   Fingerprint {}\n   Comparison code {}\n   Requested: Browser {}, Computer Use {}",
                    i + 1,
                    p.device_id.as_str(),
                    p.request_id,
                    p.fingerprint.to_hex(),
                    p.comparison_code,
                    p.browser_requested,
                    p.computer_requested
                );
            }
            let index = prompt::line("Request number to review", None)?
                .parse::<usize>()
                .map_err(|_| Failure::new("invite_pending_selection_invalid"))?;
            let p = pending
                .into_iter()
                .nth(
                    index
                        .checked_sub(1)
                        .ok_or_else(|| Failure::new("invite_pending_selection_invalid"))?,
                )
                .ok_or_else(|| Failure::new("invite_pending_selection_invalid"))?;
            if !prompt::confirm(
                "Does this exact computer's comparison code match the other computer?",
            )? {
                return Err("invite_comparison_not_confirmed".into());
            }
            let browser = p.browser_requested && prompt::confirm("Approve Browser Automation?")?;
            let computer = p.computer_requested && prompt::confirm("Approve Computer Use?")?;
            session.consent(
                "approve",
                "Approve only this computer with the capabilities just selected.",
            )?;
            let step = format!("invite-export-approve-{}", p.request_id);
            session.begin(&step)?;
            admin::approve(
                &gateway,
                admin::ApprovalSelection {
                    request_id: p.request_id,
                    device_id: p.device_id,
                    fingerprint: p.fingerprint,
                    comparison_code: p.comparison_code,
                    enable_browser: browser,
                    enable_computer: computer,
                },
            )
            .await
            .map_err(Failure::admin)?;
            session.done(&step)?;
            println!("Approved. The other computer can now finish pairing and connect.");
            return Ok(());
        }
        if tokio::time::Instant::now() >= until {
            return Err("invite_expired_without_request".into());
        }
        tokio::select! { signal=tokio::signal::ctrl_c()=>{signal.map_err(|_| Failure::new("setup_signal_failed"))?; println!("Stopped waiting. The original invitation files are retained."); return Ok(());}, _=tokio::time::sleep(Duration::from_secs(1))=>() }
    }
}
