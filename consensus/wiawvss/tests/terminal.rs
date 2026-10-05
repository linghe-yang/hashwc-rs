use types::{Error, Instance, Policy};
use wiawvss::{
    Context, Limits, Opening, PrivateShare, Public, Setup, ax,
    terminal::{self, Terminal},
};
fn fixture() -> (Setup, Context, Public, Vec<PrivateShare>) {
    let setup = Setup::new(
        Policy::from_strings(&["1"; 7].map(str::to_owned), "2").unwrap(),
        Limits::default(),
    )
    .unwrap();
    let c = Context::new(
        &setup,
        Instance {
            session: [1; 32],
            epoch: 4,
            dealer: 0,
        },
        vec![],
    )
    .unwrap();
    let (p, s) = ax::generate(
        &setup,
        &c,
        &Opening {
            message: [4; 32],
            randomness: [7; 32],
        },
    )
    .unwrap();
    (setup, c, p, s)
}
#[test]
fn valid_opening_and_each_semantic_fault_have_bounded_verifiable_evidence() {
    let (s, c, p, shares) = fixture();
    let t = terminal::recover(&s, &c, &p, &shares).unwrap();
    assert!(matches!(t, Terminal::Success(_)));
    assert!(terminal::verify(&s, &c, &p, &t));
    let mut cases = vec![];
    let mut q = p.clone();
    q.base.true_token[0] ^= 1;
    cases.push(q);
    let mut q = p.clone();
    q.base.wires[2][0] ^= 1;
    cases.push(q);
    let mut q = p.clone();
    q.base.gates[0][0][0] ^= 1;
    cases.push(q);
    let mut q = p.clone();
    q.base.tag[0] ^= 1;
    cases.push(q);
    let mut kinds = vec![];
    for q in cases {
        let t = terminal::recover(&s, &c, &q, &shares).unwrap();
        assert!(!matches!(t, Terminal::Success(_)));
        assert!(terminal::verify(&s, &c, &q, &t));
        assert!(!terminal::verify(&s, &c, &p, &t));
        let bytes = t.encode(&q);
        assert!(bytes.len() <= Terminal::MAX_BYTES);
        kinds.push(bytes[32]);
        assert_eq!(Terminal::decode(&q, &bytes).unwrap(), t);
        assert!(Terminal::decode(&p, &bytes).is_err());
    }
    assert_eq!(kinds, vec![1, 2, 3, 4]);
}
#[test]
fn unauthorized_shares_and_fake_or_noncanonical_evidence_do_not_reject_honest_dealer() {
    let (s, c, p, shares) = fixture();
    assert_eq!(
        terminal::recover(&s, &c, &p, &shares[..1]).unwrap_err(),
        Error::InsufficientShares
    );
    for t in [
        Terminal::TrueFault,
        Terminal::RootFault { token: [0; 32] },
        Terminal::InputFault {
            party: usize::MAX,
            token: [0; 32],
        },
        Terminal::GateFault {
            wire: usize::MAX,
            branches: 3,
            tokens: [[0; 32]; 2],
        },
    ] {
        assert!(!terminal::verify(&s, &c, &p, &t));
    }
    let t = terminal::recover(&s, &c, &p, &shares).unwrap();
    let mut bytes = t.encode(&p);
    bytes.push(0);
    assert!(Terminal::decode(&p, &bytes).is_err());
    assert!(Terminal::decode(&p, &[]).is_err());
}

#[test]
fn early_faults_precede_authorization_but_duplicates_never_add_weight() {
    let (s, c, p, shares) = fixture();
    let mut bad = p.clone();
    bad.base.true_token[0] ^= 1;
    assert!(matches!(
        terminal::recover(&s, &c, &bad, &[]).unwrap(),
        Terminal::TrueFault
    ));
    let mut bad = p.clone();
    bad.base.wires[2][0] ^= 1;
    assert!(matches!(
        terminal::recover(&s, &c, &bad, &shares[..1]).unwrap(),
        Terminal::InputFault { party: 0, .. }
    ));
    assert_eq!(
        terminal::recover_bounded_iter(&s, &c, &p, std::iter::repeat_n(&shares[0], 7), 256)
            .unwrap_err(),
        Error::InsufficientShares
    );
}
