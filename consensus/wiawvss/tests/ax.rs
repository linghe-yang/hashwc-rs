use crypto::{expand, hash};
use types::{Error, Instance, Policy};
use wiawvss::{Context, Limits, Opening, PrivateShare, Public, Setup, ax};
fn fixture() -> (Setup, Context, Opening, Public, Vec<PrivateShare>) {
    let p = Policy::from_strings(&["1", "2", "3", "4"].map(str::to_owned), "6").unwrap();
    let setup = Setup::new(p, Limits::default()).unwrap();
    let context = Context::new(
        &setup,
        Instance {
            session: [7; 32],
            epoch: 2,
            dealer: 0,
        },
        b"AX test".to_vec(),
    )
    .unwrap();
    let opening = Opening {
        message: [17; 32],
        randomness: [42; 32],
    };
    let (public, shares) = ax::generate(&setup, &context, &opening).unwrap();
    (setup, context, opening, public, shares)
}
#[test]
fn every_authorized_set_recovers_message_randomness_and_all_shares() {
    let (s, c, o, p, shares) = fixture();
    for mask in 0..16 {
        let selected: Vec<_> = shares
            .iter()
            .filter(|s| mask & (1 << s.party) != 0)
            .cloned()
            .collect();
        let out = ax::reconstruct(&s, &c, &p, &selected);
        if s.circuit()
            .policy()
            .authorized(selected.iter().map(|s| s.party))
            .unwrap()
        {
            let out = out.unwrap();
            assert_eq!(out.opening, o);
            assert_eq!(out.shares, shares);
        } else {
            assert_eq!(out.unwrap_err(), Error::InsufficientShares);
        }
    }
    assert!(ax::verify_opening(&s, &c, &p, &o));
}
#[test]
fn duplicates_invalid_and_stale_shares_do_not_add_weight() {
    let (s, c, _, p, shares) = fixture();
    let mut bad = shares[2].clone();
    bad.token[0] ^= 1;
    let mut stale = shares[3].clone();
    stale.context_id[0] ^= 1;
    let mut unknown = shares[0].clone();
    unknown.party = usize::MAX;
    let input = vec![shares[1].clone(), shares[1].clone(), bad, stale, unknown];
    assert_eq!(
        ax::reconstruct(&s, &c, &p, &input).unwrap_err(),
        Error::InsufficientShares
    );
    let mut enough = input;
    enough.push(shares[3].clone());
    assert!(ax::reconstruct(&s, &c, &p, &enough).is_ok());
}
#[test]
fn context_binds_session_dealer_epoch_policy_and_associated_data() {
    let (s, c, _, p, shares) = fixture();
    let mut instances = vec![c.instance().clone(); 3];
    instances[0].session[0] ^= 1;
    instances[1].dealer = 1;
    instances[2].epoch += 1;
    for i in instances {
        let other = Context::new(&s, i, c.associated_data().to_vec()).unwrap();
        assert!(!ax::verify_share(&s, &other, &p, &shares[0]));
        assert!(Public::decode(&s, &other, &p.encode()).is_err());
    }
    let other = Context::new(&s, c.instance().clone(), b"other".to_vec()).unwrap();
    assert!(!ax::verify_share(&s, &other, &p, &shares[0]));
    let other_setup = Setup::new(
        Policy::from_strings(&["1", "2", "3", "5"].map(str::to_owned), "6").unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert!(ax::share(&other_setup, &c, [0; 32]).is_err());
}
#[test]
fn all_public_fields_are_bound_including_absent_party_commitments() {
    let (s, c, o, p, shares) = fixture();
    let bytes = p.encode();
    // Touch each block and the framing, including branches not traversed by this set.
    for offset in (0..bytes.len()).step_by(32) {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        if let Ok(changed) = Public::decode(&s, &c, &changed) {
            assert!(!ax::verify_opening(&s, &c, &changed, &o));
            assert!(
                ax::reconstruct(&s, &c, &changed, &shares).is_err(),
                "offset {offset}"
            );
        }
    }
}
#[test]
fn regeneration_rejects_absent_party_tampering_even_with_valid_inner_tag_and_ax_j() {
    let (s, c, o, mut p, shares) = fixture();
    // Dealer knows all tokens and can recompute the inner MAC. J and recovered K remain valid.
    p.base.inputs[0][0] ^= 1;
    let material = expand(b"AX/derive", &[&c.id(), &o.message, &o.randomness], 128);
    let output = s.circuit().output() as u64;
    let root = hash(
        b"coins/token",
        &[&material[96..], &c.id(), &output.to_le_bytes()],
    );
    p.base.tag = [0; 32];
    p.base.tag = hash(b"transcript", &[&c.id(), &root, &p.base.encode()]);
    // Party 0 is absent; parties 1 and 3 have authorized total weight 6.
    let accepted = vec![shares[1].clone(), shares[3].clone()];
    assert!(
        wcss::reconstruct(
            &s,
            &c.id(),
            &p.base,
            &accepted
                .iter()
                .map(|x| (x.party, x.token))
                .collect::<Vec<_>>()
        )
        .is_ok()
    );
    assert_eq!(
        ax::reconstruct(&s, &c, &p, &accepted).unwrap_err(),
        Error::InvalidCommitment
    );
}
#[test]
fn canonical_fixed_layout_roundtrip_and_length_rejection() {
    let (s, c, _, p, shares) = fixture();
    let b = p.encode();
    assert_eq!(b.len(), Public::encoded_len(&s));
    assert_eq!(Public::decode(&s, &c, &b).unwrap(), p);
    for len in [0, 7, 40, 71, b.len() - 1] {
        assert!(Public::decode(&s, &c, &b[..len]).is_err());
    }
    let mut extended = b;
    extended.push(0);
    assert!(Public::decode(&s, &c, &extended).is_err());
    for share in shares {
        assert_eq!(PrivateShare::decode(&share.encode()).unwrap(), share);
        assert!(PrivateShare::decode(&share.encode()[..103]).is_err());
    }
}
#[test]
fn fresh_randomness_changes_commitments_and_noncanonical_messages_are_rejected() {
    let (s, c, _, _, _) = fixture();
    let (a, _) = ax::share(&s, &c, [0; 32]).unwrap();
    let (b, _) = ax::share(&s, &c, [0; 32]).unwrap();
    assert_ne!(a, b);
    assert!(ax::share(&s, &c, [255; 32]).is_err());
    let mut modulus = [255; 32];
    modulus[0] = 127;
    modulus[31] = 237;
    assert!(!ax::canonical_message(&modulus));
    modulus[31] -= 1;
    assert!(ax::canonical_message(&modulus));
}
