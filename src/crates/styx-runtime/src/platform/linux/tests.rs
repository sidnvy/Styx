use super::*;
use sha2::Digest;
use zbus::zvariant::Value;

fn fake_protocol_facts() -> (ListedSession, HashMap<String, OwnedValue>) {
    let path = OwnedObjectPath::try_from("/org/freedesktop/login1/session/fixture").unwrap();
    let row = (
        "fixture".to_owned(),
        1000,
        "fixture-user".to_owned(),
        "seat-test".to_owned(),
        path.clone(),
    );
    let mut p = HashMap::new();
    macro_rules! add {
        ($k:expr,$v:expr) => {
            p.insert($k.to_owned(), OwnedValue::try_from(Value::new($v)).unwrap());
        };
    }
    add!("Id", "fixture");
    add!("User", (1000_u32, path.clone()));
    add!("Seat", ("seat-test", path));
    add!("Type", "wayland");
    add!("Class", "user");
    add!("State", "active");
    add!("Remote", false);
    add!("Leader", std::process::id());
    add!("TimestampMonotonic", 1_u64);
    add!("Active", true);
    add!("LockedHint", false);
    (row, p)
}

#[test]
fn fake_protocol_same_uid_and_multiple_candidates_never_create_authority() {
    let (row, facts) = fake_protocol_facts();
    let facts = decode_facts(&row, facts).unwrap();
    let one = candidate(&facts, 1000).unwrap();
    assert_eq!(one.compositor_association, Association::Unknown);
    assert_eq!(one.agent_association, Association::Unknown);
    let mut second = one.clone();
    second.session_id = "second".to_owned();
    let snapshot = LinuxDiscoverySnapshot {
        schema: 1,
        login_unique_owner: ":1.123".to_owned(),
        candidates: vec![one, second],
        connection_closed: true,
    };
    assert_eq!(snapshot.candidates.len(), 2);
    // No selection/Ready/attach function exists in this candidate-only port.
    assert!(
        snapshot
            .candidates
            .iter()
            .all(|c| c.agent_association == Association::Unknown)
    );
}

#[test]
fn fake_protocol_capacity_identity_and_owner_changes_reject_whole_snapshot() {
    let (row, _) = fake_protocol_facts();
    assert_eq!(
        checked_list(&vec![row.clone(); 33]),
        Err(DiscoveryError::Capacity)
    );
    assert_eq!(
        checked_list(&[row.clone(), row.clone()]),
        Err(DiscoveryError::InvalidFacts)
    );
    assert_eq!(bounded(&"x".repeat(257)), Err(DiscoveryError::Capacity));
    assert_eq!(
        stable_owner(":1.1", ":1.2", 0),
        Err(DiscoveryError::OwnerChanged)
    );
    assert_eq!(
        stable_owner(":1.1", ":1.1", 1000),
        Err(DiscoveryError::UntrustedPeer)
    );
    let (_, mut facts) = fake_protocol_facts();
    facts.insert(
        "Id".to_owned(),
        OwnedValue::try_from(Value::new("different")).unwrap(),
    );
    assert_eq!(
        decode_facts(&row, facts),
        Err(DiscoveryError::SessionChanged)
    );
}

#[test]
fn fake_protocol_second_sample_rejects_changed_leader_even_if_old_pid_lives_and_changed_lock() {
    let (row, properties) = fake_protocol_facts();
    let first = decode_facts(&row, properties).unwrap();
    let mut changed_leader = first.clone();
    changed_leader.leader_pid = u32::try_from(nix::unistd::getppid().as_raw()).unwrap();
    changed_leader.leader_birth = Some(birth(changed_leader.leader_pid).unwrap());
    assert_ne!(changed_leader.leader_pid, first.leader_pid);
    assert_eq!(Some(birth(first.leader_pid).unwrap()), first.leader_birth);
    assert_eq!(
        stable_facts(&first, &changed_leader),
        Err(DiscoveryError::SessionChanged)
    );
    let mut changed_lock = first.clone();
    changed_lock.locked = !changed_lock.locked;
    assert_eq!(
        stable_facts(&first, &changed_lock),
        Err(DiscoveryError::SessionChanged)
    );
    assert_eq!(stable_facts(&first, &first), Ok(()));
    // These are changed trusted protocol facts, not an OS login or lock action.
}

#[tokio::test]
async fn fake_protocol_expired_deadline_rejects_pending_reply() {
    let deadline = Instant::now();
    let reply = before_deadline(
        deadline,
        std::future::pending::<Result<(), DiscoveryError>>(),
    )
    .await;
    assert_eq!(reply, Err(DiscoveryError::Deadline));
    // Fake pending protocol reply, not evidence of a real logind stall.
}

#[tokio::test]
#[ignore = "actual read-only Linux system bus; requires STYX_TEST_LINUX_DISCOVERY_ROOT"]
async fn actual_system_bus_snapshot_matches_independent_loginctl() {
    let root = std::path::PathBuf::from(
        std::env::var_os("STYX_TEST_LINUX_DISCOVERY_ROOT").expect("explicit owned evidence root"),
    );
    std::fs::create_dir(&root).expect("fresh evidence root");
    let uid = nix::unistd::Uid::current().as_raw();
    let start = std::time::Instant::now();
    let snapshot = discover_candidates(uid)
        .await
        .expect("actual system bus discovery");
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(2));
    assert!(snapshot.connection_closed);
    let mut ids = BTreeSet::new();
    let mut comparisons = Vec::new();
    let output = std::process::Command::new("/usr/bin/timeout")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .args([
            "--signal=KILL",
            "2s",
            "/usr/bin/loginctl",
            "list-sessions",
            "--json=short",
            "--no-pager",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let list: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for row in list
        .into_iter()
        .filter(|r| r["uid"].as_u64() == Some(u64::from(uid)))
    {
        let id = row["session"].as_str().unwrap();
        let output = std::process::Command::new("/usr/bin/timeout")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .args([
                "--signal=KILL",
                "2s",
                "/usr/bin/loginctl",
                "show-session",
                id,
                "--no-pager",
                "-p",
                "Id",
                "-p",
                "User",
                "-p",
                "Leader",
                "-p",
                "Type",
                "-p",
                "Class",
                "-p",
                "Remote",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let fields: HashMap<_, _> = text.lines().filter_map(|l| l.split_once('=')).collect();
        if fields["Class"] != "user"
            || fields["Remote"] != "no"
            || !matches!(fields["Type"], "wayland" | "x11")
        {
            continue;
        }
        ids.insert(id.to_owned());
        let c = snapshot
            .candidates
            .iter()
            .find(|c| c.session_id == id)
            .unwrap();
        let leader: u32 = fields["Leader"].parse().unwrap();
        assert_eq!(c.uid, fields["User"].parse::<u32>().unwrap());
        assert_eq!(c.leader_pid, leader);
        assert_eq!(c.leader_birth, birth(leader).unwrap());
        assert_eq!(c.agent_association, Association::Unknown);
        comparisons
            .push(serde_json::json!({"id":id,"uid":c.uid,"leader":leader,"birth":c.leader_birth,"kernel_stat":std::fs::read_to_string(format!("/proc/{leader}/stat")).unwrap()}));
    }
    assert_eq!(
        ids,
        snapshot
            .candidates
            .iter()
            .map(|c| c.session_id.clone())
            .collect()
    );
    let receipt = serde_json::json!({"schema":1,"status":"PASS","scope":"actual Linux read-only logind candidates, not Desktop/agent authorization or GUI acceptance","snapshot":snapshot,"independent_loginctl":comparisons,"elapsed_seconds":elapsed.as_secs_f64(),"source_sha256":{"mod.rs":hex::encode(sha2::Sha256::digest(include_bytes!("mod.rs"))),"tests.rs":hex::encode(sha2::Sha256::digest(include_bytes!("tests.rs")))},"observer_pid_namespace":std::fs::read_link("/proc/self/ns/pid").unwrap(),"collected_unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),"child_cleanup":"loginctl wrapped by mature timeout; output() waited for each wrapper","watcher":"NOT_IMPLEMENTED"});
    std::fs::write(
        root.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}
