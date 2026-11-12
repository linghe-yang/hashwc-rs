use types::{Error, Instance, Policy};
use wcss::{Limits, Setup};
use wiawvss::{Context, Opening, PrivateShare, ax, compact};
fn fixture() -> (Setup, Context, Opening) {
    let policy = Policy::from_strings(&["3", "2", "4", "3"].map(str::to_string), "4").unwrap();
    let setup = Setup::new(policy, Limits::default()).unwrap();
    let context = Context::new(
        &setup,
        Instance {
            session: [7; 32],
            epoch: 3,
            dealer: 1,
        },
        b"compact-test".to_vec(),
    )
    .unwrap();
    let mut message = [0; 32];
    message[31] = 19;
    (
        setup,
        context,
        Opening {
            message,
            randomness: [11; 32],
        },
    )
}
#[test]
fn compact_css_ax_recovers_every_authorized_subset_without_wire_digests() {
    let (setup, context, opening) = fixture();
    let (public, shares) = compact::generate(&setup, &context, &opening).unwrap();
    let (full, full_shares) = ax::generate(&setup, &context, &opening).unwrap();
    assert_eq!(full_shares, shares);
    assert_eq!(
        public.byte_len(),
        296 + 32 * 4 + 64 * setup.circuit().gates().len()
    );
    assert_eq!(
        full.byte_len() - public.byte_len(),
        32 * setup.circuit().nodes()
    );
    assert_eq!(
        compact::Public::decode(&setup, &context, &public.encode()).unwrap(),
        public
    );
    for mask in 0..16 {
        let selected = shares
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, s)| s.clone())
            .collect::<Vec<_>>();
        let recovered = compact::reconstruct(&setup, &context, &public, &selected);
        let encoded = public.encode();
        let view = compact::PublicView::decode(&setup, &context, &encoded).unwrap();
        assert_eq!(view.digest(), public.digest());
        assert!(public.matches_encoded(&encoded));
        let borrowed = view.reconstruct(&setup, &context, &selected);
        if setup
            .circuit()
            .policy()
            .authorized(selected.iter().map(|s| s.party))
            .unwrap()
        {
            assert_eq!(recovered.unwrap().opening, opening);
            assert_eq!(borrowed.unwrap().opening, opening);
        } else {
            assert!(matches!(recovered, Err(Error::InsufficientShares)));
            assert!(matches!(borrowed, Err(Error::InsufficientShares)));
        }
    }
}
#[test]
fn duplicate_and_invalid_tokens_are_pending_not_dealer_rejection() {
    let (setup, context, opening) = fixture();
    let (public, shares) = compact::generate(&setup, &context, &opening).unwrap();
    let duplicates = vec![shares[0].clone(); 8]; // weight 3, not 24.
    assert!(matches!(
        compact::reconstruct(&setup, &context, &public, &duplicates),
        Err(Error::InsufficientShares)
    ));
    let mut corrupted = shares[1].clone();
    corrupted.token[0] ^= 1;
    assert!(!compact::verify_share(
        &setup, &context, &public, &corrupted
    ));
    assert!(matches!(
        compact::reconstruct(&setup, &context, &public, &[shares[0].clone(), corrupted]),
        Err(Error::InsufficientShares)
    ));
}
#[test]
fn valid_input_receipts_do_not_certify_a_corrupt_ax_commitment() {
    let (setup, context, opening) = fixture();
    let (mut public, shares) = compact::generate(&setup, &context, &opening).unwrap();
    public.commitment[0] ^= 1;
    assert!(
        shares
            .iter()
            .all(|s| compact::verify_share(&setup, &context, &public, s))
    );
    assert!(!compact::verify_opening(
        &setup, &context, &public, &opening
    ));
    for selected in [&shares[..2], &shares[2..], &shares[..]] {
        assert!(matches!(
            compact::reconstruct(&setup, &context, &public, selected),
            Err(Error::InvalidCommitment)
        ));
    }
}
#[test]
fn canonical_public_encoding_is_context_bound_and_checks_every_field() {
    let (setup, context, opening) = fixture();
    let (public, shares) = compact::generate(&setup, &context, &opening).unwrap();
    let raw = public.encode();
    assert!(compact::Public::decode(&setup, &context, &raw[..raw.len() - 1]).is_err());
    let full = ax::generate(&setup, &context, &opening).unwrap().0.encode();
    assert!(compact::Public::decode(&setup, &context, &full).is_err());
    let other = Context::new(
        &setup,
        Instance {
            session: [8; 32],
            epoch: 3,
            dealer: 1,
        },
        vec![],
    )
    .unwrap();
    assert!(compact::Public::decode(&setup, &other, &raw).is_err());
    for offset in (72..raw.len()).step_by(32) {
        let mut bytes = raw.clone();
        bytes[offset] ^= 1;
        let altered = compact::Public::decode(&setup, &context, &bytes).unwrap();
        let view = compact::PublicView::decode(&setup, &context, &bytes).unwrap();
        assert!(!compact::verify_opening(
            &setup, &context, &altered, &opening
        ));
        assert!(
            matches!(
                compact::reconstruct(&setup, &context, &altered, &shares),
                Err(Error::InvalidCommitment)
            ),
            "offset {offset}"
        );
        assert!(
            matches!(
                view.reconstruct(&setup, &context, &shares),
                Err(Error::InvalidCommitment)
            ),
            "borrowed recovery accepted modified offset {offset}"
        );
    }
}
#[test]
fn valid_css_with_wrong_ax_randomness_still_fails_full_regeneration() {
    // A syntactically valid but unrelated CSS shares the same key and uses a different seed.
    // Its own transcript tag is valid. Only full deterministic AX regeneration detects it.
    let (setup, context, opening) = fixture();
    let (mut public, _) = compact::generate(&setup, &context, &opening).unwrap();
    let mut material = [0; 128];
    crypto::expand_into(
        b"AX/derive",
        &[&context.id, &opening.message, &opening.randomness],
        &mut material,
    );
    let key: crypto::Block = material[64..96].try_into().unwrap();
    let (base, tokens) = wcss::compact::share(&setup, &context.id, &key, &[99; 32]);
    public.base = base;
    let shares = tokens
        .iter()
        .enumerate()
        .map(|(party, &token)| PrivateShare {
            setup_id: setup.id(),
            context_id: context.id,
            party,
            token,
        })
        .collect::<Vec<_>>();
    assert!(
        shares
            .iter()
            .all(|s| compact::verify_share(&setup, &context, &public, s))
    );
    assert_eq!(
        wcss::compact::reconstruct(
            &setup,
            &context.id,
            &public.base,
            &shares
                .iter()
                .map(|s| (s.party, s.token))
                .collect::<Vec<_>>()
        )
        .unwrap(),
        key
    );
    assert!(matches!(
        compact::reconstruct(&setup, &context, &public, &shares),
        Err(Error::InvalidCommitment)
    ));
    let encoded = public.encode();
    let view = compact::PublicView::decode(&setup, &context, &encoded).unwrap();
    assert!(matches!(
        view.reconstruct(&setup, &context, &shares),
        Err(Error::InvalidCommitment)
    ));
}

#[test]
fn borrowed_compact_recovery_ignores_bad_and_stale_candidates_without_false_rejection() {
    let (setup, context, opening) = fixture();
    let (public, shares) = compact::generate(&setup, &context, &opening).unwrap();
    let bytes = public.encode();
    let view = compact::PublicView::decode(&setup, &context, &bytes).unwrap();
    let mut invalid = shares[1].clone();
    invalid.token[0] ^= 1;
    let mut stale = shares[1].clone();
    stale.context_id[0] ^= 1;
    let mut outside = shares[1].clone();
    outside.party = usize::MAX;
    assert!(shares.iter().all(|s| view.verify_share(s)));
    assert!(
        !view.verify_share(&invalid) && !view.verify_share(&stale) && !view.verify_share(&outside)
    );
    assert!(matches!(
        view.reconstruct(
            &setup,
            &context,
            [&shares[0], &shares[0], &invalid, &stale, &outside]
        ),
        Err(Error::InsufficientShares)
    ));
    assert_eq!(
        view.reconstruct(
            &setup,
            &context,
            [&shares[0], &invalid, &shares[1], &stale, &outside]
        )
        .unwrap()
        .opening,
        opening
    );
    let mut wrong_context = context.clone();
    wrong_context.id[0] ^= 1;
    assert!(view.reconstruct(&setup, &wrong_context, &shares).is_err());
    for len in [0, 8, 72, bytes.len() - 1] {
        assert!(compact::PublicView::decode(&setup, &context, &bytes[..len]).is_err());
    }
    let mut other = bytes.clone();
    other[8] ^= 1;
    assert!(compact::PublicView::decode(&setup, &context, &other).is_err());
    assert!(!public.matches_encoded(&other));
}
