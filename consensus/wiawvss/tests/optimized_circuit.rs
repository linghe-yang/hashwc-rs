use sdc_types::{InstanceId, Weight, WeightedMembership};
use types::{Error, Instance, Policy};
use wavid::Codec;
use wiawvss::{
    Context, Limits, Opening, Public, Setup, ax,
    certified::{self, Evidence, Header, Receipt},
    terminal::{self, Terminal},
};

#[test]
fn optimized_layout_supports_receipts_success_faults_and_cross_setup_rejection() {
    for weights in [
        vec![3u64; 8],
        vec![2, 3, 4, 2, 3, 4, 2, 4],
        vec![6, 9, 12, 6, 9, 12, 6, 12],
    ] {
        let threshold = weights.iter().sum::<u64>() / 3;
        let p = Policy::new(
            weights.iter().copied().map(Into::into).collect(),
            threshold.into(),
        )
        .unwrap();
        let old = Setup::new(p.clone(), Limits::default()).unwrap();
        let s = Setup::new_optimized(p, Limits::default()).unwrap();
        let c = Context::new(
            &s,
            Instance {
                session: [3; 32],
                epoch: 1,
                dealer: 0,
            },
            vec![9],
        )
        .unwrap();
        assert!(c.validate(&old).is_err());
        let m = WeightedMembership::new(
            weights.iter().copied().map(Weight::from).collect(),
            Weight::from(threshold),
        )
        .unwrap();
        let codec = Codec::new(
            &m,
            InstanceId::new(1, Some(0), 0),
            [7; 32],
            Public::encoded_len(&s),
        )
        .unwrap();
        let mut message = [0; 32];
        message[31] = 17;
        let o = Opening {
            message,
            randomness: [61; 32],
        };
        let (public, shares) = ax::generate(&s, &c, &o).unwrap();
        assert_eq!(
            public.encode().len(),
            360 + 64 * weights.len() + 96 * s.circuit.gates.len()
        );
        let prepared = codec.prepare(&public.encode()).unwrap();
        let h = Header::new(&s, &c, prepared.root);
        for share in &shares {
            let receipt = Receipt::new(&s, &codec, &prepared, share).unwrap();
            assert!(receipt.verify(&s, &c, &codec, &h, share.party).is_some());
        }
        let mut count = 0;
        while !s.circuit.policy.authorized(0..count).unwrap() {
            count += 1;
        }
        assert!(matches!(
            terminal::recover_bounded(&s, &c, &public, &shares[..count - 1], 8),
            Err(Error::InsufficientShares)
        ));
        let t = terminal::recover_bounded(&s, &c, &public, &shares[..count], 8).unwrap();
        assert!(matches!(&t,Terminal::Success(out) if *out == o));
        let cert = certified::certify(&s, &codec, &h, &prepared, t).unwrap();
        assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
        assert!(!certified::verify(&old, &c, &codec, &h, &cert, 8));
        assert!(!certified::verify(&s, &c, &codec, &h, &cert, 4));
        for kind in 0..5 {
            let mut bad = public.clone();
            match kind {
                0 => bad.base.true_token[0] ^= 1,
                1 => bad.base.wires[2][0] ^= 1,
                2 => {
                    for g in &mut bad.base.gates {
                        g[0][0] ^= 1;
                        g[1][0] ^= 1;
                    }
                }
                3 => bad.commitment[0] ^= 1,
                _ => bad.base.tag[0] ^= 1,
            }
            let prepared = codec.prepare(&bad.encode()).unwrap();
            let h = Header::new(&s, &c, prepared.root);
            let t = terminal::recover_bounded(&s, &c, &bad, &shares, 8).unwrap();
            assert!(!matches!(t, Terminal::Success(_)));
            let cert = certified::certify(&s, &codec, &h, &prepared, t).unwrap();
            assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
            let mut forged = cert.clone();
            if let Evidence::Semantic { fields, .. } = &mut forged.evidence {
                fields[0].fragment.data[0] ^= 1;
            } else {
                panic!("expected authenticated semantic fault");
            }
            assert!(!certified::verify(&s, &c, &codec, &h, &forged, 8));
        }
    }
}
