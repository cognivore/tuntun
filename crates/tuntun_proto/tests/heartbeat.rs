use std::time::Duration;
use tuntun_proto::heartbeat::Heartbeat;

#[test]
fn three_misses_drop_the_session_and_wrong_pongs_do_not_extend_it() {
    let mut heartbeat = Heartbeat::new(100);
    for (probe, timeout) in [(15, 20), (30, 35)] {
        let ping = heartbeat
            .poll(Duration::from_secs(probe))
            .expect("probe")
            .expect("ping");
        heartbeat.on_pong(ping.nonce + 1);
        assert!(heartbeat
            .poll(Duration::from_secs(timeout))
            .expect("retry allowed")
            .is_none());
    }
    let ping = heartbeat
        .poll(Duration::from_secs(45))
        .expect("last probe")
        .expect("ping");
    let error = heartbeat
        .poll(Duration::from_secs(50))
        .expect_err("dead session");
    assert_eq!(error.missed, 3);
    assert_eq!(error.nonce, ping.nonce);
}

#[test]
fn matching_pong_resets_consecutive_misses() {
    let mut heartbeat = Heartbeat::new(0);
    heartbeat.poll(Duration::from_secs(15)).expect("ping");
    heartbeat.poll(Duration::from_secs(20)).expect("first miss");
    let ping = heartbeat
        .poll(Duration::from_secs(30))
        .expect("ping")
        .expect("probe");
    heartbeat.on_pong(ping.nonce);
    heartbeat.poll(Duration::from_secs(45)).expect("next ping");
    assert!(heartbeat.poll(Duration::from_secs(50)).is_ok());
}
