use sdc_types::{InstanceId, Weight, WeightedMembership};
use types::{Instance, Policy};
use wavid::{Codec, Retrieval, StorageFault};
use wiawvss::{
    Context, Limits, Opening, Public, Setup, ax,
    certified::{self, Certificate, Evidence, Header, Receipt},
    terminal::{self, Terminal},
};
fn fixture() -> (Setup, Context, Codec, Opening) {
    let s = Setup::new(
        Policy::from_strings(&vec!["3".into(); 4], "4").unwrap(),
        Limits::default(),
    )
    .unwrap();
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
    let m = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    let codec = Codec::new(
        &m,
        InstanceId::new(1, Some(0), 0),
        [7; 32],
        Public::encoded_len(&s),
    )
    .unwrap();
    let mut message = [0; 32];
    message[31] = 17;
    (
        s,
        c,
        codec,
        Opening {
            message,
            randomness: [61; 32],
        },
    )
}
#[test]
fn header_is_constant_and_receipts_authenticate_both_digests_and_positions() {
    let (s, c, codec, o) = fixture();
    let (p, shares) = ax::generate(&s, &c, &o).unwrap();
    let prepared = codec.prepare(&p.encode()).unwrap();
    let h = Header::new(&s, &c, prepared.root);
    assert_eq!(h.encode().len(), 112);
    assert_eq!(Header::decode(&s, &c, &h.encode()).unwrap(), h);
    for share in shares {
        let r = Receipt::new(&s, &codec, &prepared, &share).unwrap();
        assert!(r.verify(&s, &c, &codec, &h, share.party).is_some());
        let raw = r.encode();
        assert!(Receipt::decode(&codec, &raw).is_ok());
        let mut bad = r.clone();
        bad.share[103] ^= 1;
        assert!(bad.verify(&s, &c, &codec, &h, share.party).is_none());
        let mut bad = r.clone();
        bad.fields[0].fragment.index = codec.k;
        assert!(bad.verify(&s, &c, &codec, &h, share.party).is_none());
        let mut bad = r.clone();
        bad.fields.pop();
        assert!(bad.verify(&s, &c, &codec, &h, share.party).is_none());
        let mut wrong = h.clone();
        wrong.root[0] ^= 1;
        assert!(r.verify(&s, &c, &codec, &wrong, share.party).is_none());
    }
    let mut bad = p.clone();
    bad.base.wires[2][0] ^= 1;
    let prep = codec.prepare(&bad.encode()).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let (_, shares) = ax::generate(&s, &c, &o).unwrap();
    let r = Receipt::new(&s, &codec, &prep, &shares[0]).unwrap();
    assert!(r.verify(&s, &c, &codec, &h, 0).is_none());
}
#[test]
fn success_is_verified_from_header_only_and_binds_range_and_every_bulk_byte() {
    let (s, c, codec, o) = fixture();
    let (mut p, _) = ax::generate(&s, &c, &o).unwrap();
    let h = Header::new(&s, &c, codec.prepare(&p.encode()).unwrap().root);
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Success(o.clone()),
    };
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    assert!(!certified::verify(&s, &c, &codec, &h, &cert, 4));
    assert!(cert.encode().len() < 128);
    p.commitment[0] ^= 1;
    let h = Header::new(&s, &c, codec.prepare(&p.encode()).unwrap().root);
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Success(o),
    };
    assert!(!certified::verify(&s, &c, &codec, &h, &cert, 8));
}
#[test]
fn semantic_certificates_need_only_authenticated_local_fields() {
    let (s, c, codec, o) = fixture();
    let (original, shares) = ax::generate(&s, &c, &o).unwrap();
    for kind in 0..5 {
        let mut p = original.clone();
        match kind {
            0 => p.base.true_token[0] ^= 1,
            1 => p.base.wires[2][0] ^= 1,
            2 => {
                for g in &mut p.base.gates {
                    g[0][0] ^= 1;
                    g[1][0] ^= 1;
                }
            }
            3 => p.commitment[0] ^= 1,
            _ => p.base.tag[0] ^= 1,
        };
        let prepared = codec.prepare(&p.encode()).unwrap();
        let h = Header::new(&s, &c, prepared.root);
        let t = terminal::recover_bounded(&s, &c, &p, &shares, 8).unwrap();
        assert!(!matches!(t, Terminal::Success(_)));
        let cert = certified::certify(&s, &codec, &h, &prepared, t).unwrap();
        assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
        let mut bad = cert.clone();
        if let Evidence::Semantic { fields, .. } = &mut bad.evidence {
            fields[0].fragment.data[0] ^= 1;
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &bad, 8));
        let mut bad = cert.clone();
        if let Evidence::Semantic { fields, .. } = &mut bad.evidence {
            fields.clear();
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &bad, 8));
    }
}
#[test]
fn out_of_range_candidate_requires_authenticated_output_token() {
    let (s, c, codec, o) = fixture();
    let (p, shares) = ax::generate(&s, &c, &o).unwrap();
    let prep = codec.prepare(&p.encode()).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let t = terminal::recover_bounded(&s, &c, &p, &shares, 4).unwrap();
    assert!(matches!(t, Terminal::RootFault { .. }));
    let cert = certified::certify(&s, &codec, &h, &prep, t).unwrap();
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 4));
    assert!(!certified::verify(&s, &c, &codec, &h, &cert, 8));
    let forged = certified::certify(
        &s,
        &codec,
        &h,
        &prep,
        Terminal::RootFault { token: [0; 32] },
    )
    .unwrap();
    assert!(!certified::verify(&s, &c, &codec, &h, &forged, 4));
}
#[test]
fn format_coding_padding_and_cross_instance_proofs() {
    let (s, c, codec, o) = fixture();
    let (p, _) = ax::generate(&s, &c, &o).unwrap();
    let mut raw = p.encode();
    raw[0] ^= 1;
    let prep = codec.prepare(&raw).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Format(certified::openings(&codec, &prep, &[(0, 72)]).unwrap()),
    };
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    let mut rows = codec.prepare(&p.encode()).unwrap().rows;
    rows[0][codec.k][0] ^= 1;
    let prep = codec.commit_rows(rows).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let rows = prep
        .rows
        .iter()
        .enumerate()
        .map(|(z, r)| {
            (0..codec.k)
                .map(|i| {
                    (
                        i,
                        wavid::Fragment {
                            index: i,
                            data: r[i],
                            proof: prep.stripes[z].proof(i),
                        },
                    )
                })
                .collect()
        })
        .collect::<Vec<_>>();
    let roots = prep.stripes.iter().map(|t| t.root()).collect::<Vec<_>>();
    let Some(Retrieval::Invalid(fault)) = codec.recover(h.root, &roots, &rows).unwrap() else {
        panic!("coding fault")
    };
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Storage(fault),
    };
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    let mut rows = codec.prepare(&p.encode()).unwrap().rows;
    let pos = codec.file_bytes;
    rows[pos / (32 * codec.k)][(pos / 32) % codec.k][pos % 32] = 1;
    let prep = codec.commit_rows(rows).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let proof = codec.source_opening(&prep, pos / 32).unwrap();
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Storage(StorageFault::Padding(proof)),
    };
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    let m = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    let other = Codec::new(
        &m,
        InstanceId::new(1, Some(1), 0),
        [7; 32],
        codec.file_bytes,
    )
    .unwrap();
    assert!(!certified::verify(&s, &c, &other, &h, &cert, 8));
}
