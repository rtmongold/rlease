use std::process::Command;

#[test]
fn help_exits_2_and_prints_usage() {
    let bin = env!("CARGO_BIN_EXE_rlease");
    let out = Command::new(bin).arg("-h").output().expect("run rlease");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage: rlease"));
    assert!(stderr.contains("-i"));
}
