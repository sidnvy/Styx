//! Hermetic contract checks, not launchd/permissions/native persistence proof.
use super::*;
fn print_fixture(extra: &str) -> String {
    format!(
        "system/app.styx.native.501.test.host = {{\n path = /Library/LaunchDaemons/app.styx.native.501.test.host.plist\n state = running\n program = /Users/sid/private/bin/styx\n username = sid\n arguments = {{\n /Users/sid/private/bin/styx\n __service-run\n --state-dir\n /Users/sid/Library/Application Support/Styx/profile\n --role\n host\n }}\n runs = 1\n pid = 123\n {extra}\n environment = {{\n PATH => /usr/bin:/bin\n }}\n}}\n"
    )
}
#[test]
fn fixed_definition_and_closed_job_observation_contract() {
    let raw = definition_bytes(
        "app.styx.native.501.test.host",
        "sid",
        Path::new("/Users/sid"),
        Path::new("/Users/sid/private/bin/styx"),
        Path::new("/Users/sid/Library/Application Support/Styx/A&B"),
        ServiceRole::Host,
    )
    .unwrap();
    let text = String::from_utf8(raw).unwrap();
    assert!(text.contains("A&amp;B"));
    assert!(text.contains("<key>UserName</key><string>sid</string>"));
    assert!(text.contains("<key>KeepAlive</key><false/>"));
    assert!(!text.contains("sudo"));
    assert!(!text.contains("node"));
    assert!(
        definition_bytes(
            "label",
            "sid",
            Path::new("/Users/sid"),
            Path::new("/Users/sid/private/bin/styx"),
            Path::new("/Users/sid/../other"),
            ServiceRole::Host
        )
        .is_err()
    );
    let v = parse_print(
        print_fixture("").as_bytes(),
        "app.styx.native.501.test.host",
    )
    .unwrap();
    assert_eq!(v.pid, Some(123));
    assert_eq!(v.runs, 1);
    assert_eq!(v.arguments.len(), 6);
    assert_eq!(
        v.arguments[3],
        "/Users/sid/Library/Application Support/Styx/profile"
    );
    assert_eq!(
        parse_print(
            print_fixture("pid = 456").as_bytes(),
            "app.styx.native.501.test.host"
        ),
        Err(ServiceError::Conflict)
    );
    assert!(
        parse_print(
            print_fixture("").as_bytes(),
            "app.styx.native.501.other.host"
        )
        .is_err()
    );
    assert!(
        parse_print(
            print_fixture("").replace("pid = 123", "pid = 0").as_bytes(),
            "app.styx.native.501.test.host"
        )
        .is_err()
    );
    assert!(
        parse_print(
            print_fixture("")
                .replace("runs = 1", "runs = unknown")
                .as_bytes(),
            "app.styx.native.501.test.host"
        )
        .is_err()
    );
    assert!(
        parse_print(
            print_fixture("").trim_end_matches("}\n").as_bytes(),
            "app.styx.native.501.test.host"
        )
        .is_err()
    );
}

#[test]
fn disabled_override_observation_is_not_inferred_from_garbage() {
    assert_eq!(
        parse_disabled(b"disabled services = {\n \"target\" => true\n}\n", "target"),
        Ok(false)
    );
    assert_eq!(
        parse_disabled(b"disabled services = {\n \"other\" => true\n}\n", "target"),
        Ok(true)
    );
    assert!(parse_disabled(b"unrecognized empty output", "target").is_err());
    assert!(
        parse_disabled(
            b"disabled services = {\n \"target\" => maybe\n}\n",
            "target"
        )
        .is_err()
    );
    assert!(
        parse_disabled(
            b"disabled services = {\n \"target\" => true\n \"target\" => false\n}\n",
            "target"
        )
        .is_err()
    );
}

/// Native Darwin socket regression, not a launchd or service-readiness proof.
#[test]
fn ordinary_state_root_socket_roundtrip_and_oversized_preflight() {
    use std::{
        io::{Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::DirBuilderExt,
            net::{UnixListener, UnixStream},
        },
    };
    let base = Path::new("/private/tmp");
    let mut name = format!("styx-socket-{}-", uuid::Uuid::new_v4().simple());
    let padding = 85 - base.as_os_str().as_bytes().len() - 1 - name.len();
    name.push_str(&"x".repeat(padding));
    let root = base.join(name);
    assert_eq!(root.as_os_str().as_bytes().len(), 85);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    let old = root.join(".styx-service-control-v1.sock");
    assert!(
        UnixListener::bind(&old).is_err(),
        "old 115-byte endpoint cannot bind on Darwin"
    );
    validate_control_path(&root).unwrap();
    let endpoint = root.join(CONTROL_SOCKET_NAME);
    let listener = UnixListener::bind(&endpoint).unwrap();
    let mut client = UnixStream::connect(&endpoint).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    client.write_all(&nonce).unwrap();
    let mut observed = [0; 16];
    server.read_exact(&mut observed).unwrap();
    assert_eq!(observed, nonce);
    assert!(validate_control_path(&base.join("x".repeat(104))).is_err());
    drop((client, server, listener));
    std::fs::remove_file(&endpoint).unwrap();
    std::fs::remove_dir(&root).unwrap();
}
