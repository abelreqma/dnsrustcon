//! Live, network-dependent end-to-end tests.
//!
//! These run the compiled binary against real OSINT sources and a real
//! resolver, so they need working network access. They are marked `#[ignore]`
//! and never run during a normal `cargo test`, which keeps the default suite
//! offline and deterministic. Run them explicitly with:
//!
//!     cargo test -- --ignored
//!
//! Because they depend on third-party services and live DNS, the assertions
//! stay lenient about the exact hosts and ASNs found and only check the report
//! structure that always prints.

use std::process::Command;

#[test]
#[ignore = "requires network access"]
fn passive_domain_scan_renders_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_dnsrustcon"))
        .args([
            "example.com",
            "--mode",
            "passive",
            "--no-color",
            "--timeout",
            "10",
        ])
        .output()
        .expect("failed to run dnsrustcon");

    assert!(
        output.status.success(),
        "process exited with failure: {:?}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The report header and these two section labels always print, regardless
    // of what the network turned up.
    assert!(
        stdout.contains("dnsrustcon"),
        "missing report header in output"
    );
    assert!(stdout.contains("SUBDOMAINS"), "missing SUBDOMAINS section");
    assert!(
        stdout.contains("IP INTELLIGENCE"),
        "missing IP INTELLIGENCE section"
    );
}

#[test]
#[ignore = "requires network access"]
fn passive_ip_target_enriches() {
    let output = Command::new(env!("CARGO_BIN_EXE_dnsrustcon"))
        .args(["8.8.8.8", "--no-color", "--timeout", "10"])
        .output()
        .expect("failed to run dnsrustcon");

    assert!(
        output.status.success(),
        "process exited with failure: {:?}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The IP intelligence section always prints, and the target IP should show
    // up in the enrichment output. The ASN itself is network-dependent, so it
    // is not asserted.
    assert!(
        stdout.contains("IP INTELLIGENCE"),
        "missing IP INTELLIGENCE section"
    );
    assert!(stdout.contains("8.8.8.8"), "target IP missing from output");
}
