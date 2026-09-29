use tuntun_core::{LocalPort, ServicePort};

#[test]
fn deserialization_enforces_the_same_port_contract_as_construction() {
    assert!(LocalPort::new(0).is_err());
    assert!(serde_json::from_str::<LocalPort>("0").is_err());
    assert!(serde_json::from_str::<ServicePort>("0").is_err());
    let port: LocalPort = serde_json::from_str("22").expect("valid SSH port");
    assert_eq!(port.value(), 22);
}
