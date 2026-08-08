use deopti_transfer::dlog::dlog;
use deopti_transfer::fountain::{frame_indices, LtEncoder};
use deopti_transfer::frame::{fnv1a, frame_checksum, pack_frame, FrameHeader, HEADER_LEN};
use deopti_transfer::soliton::soliton_cdf;

fn test_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 37 + (i >> 8) * 11) & 0xff) as u8)
        .collect()
}

fn fnv_of_f64s(values: &[f64]) -> u32 {
    let mut buf = Vec::with_capacity(values.len() * 8);
    for v in values {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fnv1a(&buf)
}

#[test]
#[allow(clippy::approx_constant)]
fn dlog_spot_values() {
    let golden: [(f64, f64); 11] = [
        (1.0, 0.0),
        (1.5, 0.4054651081081644),
        (2.0, 0.6931471805599453),
        (2.718281828459045, 1.0),
        (10.0, 2.3025850929940455),
        (20.0, 2.995732273553991),
        (200.0, 5.298317366548036),
        (2000.0, 7.600902459542082),
        (2986.0, 8.001689978099137),
        (44000.0, 10.691944912900398),
        (131070.0, 11.78348681061359),
    ];
    for (x, expected) in golden {
        assert_eq!(dlog(x), expected, "dlog({x})");
    }
}

#[test]
fn dlog_exhaustive_fingerprint() {
    let mut values = Vec::with_capacity(65535 + (64 * 4096 - 64));
    for k in 1..=65535usize {
        values.push(dlog(2.0 * k as f64));
    }
    for i in 64..(64 * 4096) {
        values.push(dlog(i as f64 / 64.0));
    }
    assert_eq!(fnv_of_f64s(&values), 0x27b0_f3cc, "dlog drifted");
}

#[test]
fn soliton_cdf_fingerprints() {
    let golden: [(usize, u32); 7] = [
        (1, 0x8c6a_9878),
        (2, 0x2417_b297),
        (17, 0x2ba4_1e3c),
        (179, 0xe8b6_340a),
        (716, 0x28d3_1438),
        (5000, 0x357a_4c9a),
        (22000, 0xfc51_2a92),
    ];
    for (k, expected) in golden {
        let cdf = soliton_cdf(k);
        assert_eq!(cdf.len(), k);
        assert_eq!(fnv_of_f64s(&cdf), expected, "k={k} distribution drifted");
    }
}

#[test]
fn frame_indices_subsets() {
    let seqs: [u32; 5] = [0, 1, 2, 41, 1000];
    let golden: [(usize, [&[u32]; 5]); 5] = [
        (1, [&[0], &[0], &[0], &[0], &[0]]),
        (2, [&[1], &[1], &[1], &[0], &[1]]),
        (
            17,
            [&[3, 14], &[12, 0], &[6, 8], &[15, 16, 13], &[11, 2, 16]],
        ),
        (
            179,
            [
                &[27, 39],
                &[30, 55],
                &[155, 125],
                &[28, 132, 88],
                &[39, 75, 24],
            ],
        ),
        (
            716,
            [
                &[27, 397],
                &[567, 592],
                &[155, 304],
                &[386, 311, 625],
                &[39, 433, 382],
            ],
        ),
    ];
    for (k, expected) in golden {
        let cdf = soliton_cdf(k);
        for (i, seq) in seqs.iter().enumerate() {
            let actual = frame_indices(k, &cdf, 4242, *seq);
            assert_eq!(&actual[..], expected[i], "k={k} seq={seq}");
        }
    }
}

#[test]
fn encoded_stream_fingerprints() {
    let golden: [(usize, usize, u32, u32); 4] = [
        (1, 64, 1, 0xf6a1_15c5),
        (23, 64, 7, 0x2aaf_e48d),
        (179, 2933, 4242, 0x83bb_d1d7),
        (716, 1445, 65535, 0x15e1_0360),
    ];
    for (k, block_len, session_id, expected) in golden {
        let payload = test_payload(k * block_len - 7);
        let mut encoder = LtEncoder::new(&payload, block_len, session_id);
        assert_eq!(encoder.k(), k);
        let mut stream = Vec::with_capacity(64 * block_len);
        for seq in 0..64u32 {
            stream.extend_from_slice(&encoder.encode(seq));
        }
        assert_eq!(fnv1a(&stream), expected, "k={k}/{block_len}/{session_id}");
    }
}

#[test]
fn systematic_encoded_stream_fingerprints() {
    let golden: [(usize, usize, u32, u32); 4] = [
        (1, 64, 1, 0xf6a1_15c5),
        (23, 64, 7, 0xc65d_671a),
        (179, 2933, 4242, 0x54f7_8d05),
        (716, 1445, 65535, 0x75b7_3b85),
    ];
    for (k, block_len, session_id, expected) in golden {
        let payload = test_payload(k * block_len - 7);
        let mut encoder = LtEncoder::new_systematic(&payload, block_len, session_id);
        let mut stream = Vec::with_capacity(64 * block_len);
        for seq in 0..64u32 {
            stream.extend_from_slice(&encoder.encode(seq));
        }
        assert_eq!(fnv1a(&stream), expected, "k={k}/{block_len}/{session_id}");
    }
}

#[test]
fn causal_encoded_stream_fingerprints() {
    let cases: [(usize, usize, u32); 4] = [
        (1, 64, 1),
        (23, 64, 7),
        (179, 2933, 4242),
        (716, 1445, 65535),
    ];
    let actual: Vec<u32> = cases
        .into_iter()
        .map(|(k, block_len, session_id)| {
            let payload = test_payload(k * block_len - 7);
            let mut encoder = LtEncoder::new_causal(&payload, block_len, session_id);
            let mut stream = Vec::with_capacity(64 * block_len);
            for seq in 0..64u32 {
                stream.extend_from_slice(&encoder.encode(seq));
            }
            fnv1a(&stream)
        })
        .collect();
    assert_eq!(
        actual,
        vec![0xf6a1_15c5, 0x493f_7d92, 0x5a27_8a67, 0x088f_9b09]
    );
}

#[test]
fn frame_header_wire_bytes() {
    let block_bytes = [1, 2, 3, 4, 5, 6];
    let mut header = FrameHeader {
        flags: 0,
        session_id: 0xbeef,
        seq: 0x0102_0304,
        k: 0x0111,
        block_len: 6,
        total_len: 0x00fe_dcba,
        stream_tag: 0x89ab_cdef,
        frame_tag: 0,
    };
    header.frame_tag = frame_checksum(&header, &block_bytes);
    let frame = pack_frame(&header, &block_bytes);
    assert_eq!(frame.len(), HEADER_LEN + 6);
    let hex: Vec<String> = frame.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex.join(" "),
        "d1 0f 00 ef be 04 03 02 01 11 01 06 00 ba dc fe 00 ef cd ab 89 d6 d8 ac 55 01 02 03 04 05 06"
    );
    let (parsed, block) = deopti_transfer::parse_frame(&frame).expect("round trip");
    assert_eq!(parsed, header);
    assert_eq!(block, &[1, 2, 3, 4, 5, 6]);
}

#[test]
fn fnv1a_values() {
    assert_eq!(fnv1a(b"decimen optical transfer"), 0x8cae_faad);
    assert_eq!(fnv1a(b""), 0x811c_9dc5);
}
