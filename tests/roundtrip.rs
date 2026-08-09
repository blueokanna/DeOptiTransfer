use deopti_transfer::container::{
    is_precompressed_type, pack_file, unpack_file, verify_file, Compression,
};
use deopti_transfer::fountain::{LtDecoder, LtEncoder};
use deopti_transfer::prng::SplitMix32;
use deopti_transfer::session::{Receiver, ReceiverLimits, Sender};
use deopti_transfer::Error;

fn test_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 37 + (i >> 8) * 11) & 0xff) as u8)
        .collect()
}

struct RoundTrip {
    overhead: f64,
    recovered: Option<Vec<u8>>,
}

fn round_trip(byte_length: usize, block_len: usize, session_id: u32, drop_rate: f64) -> RoundTrip {
    let payload = test_payload(byte_length);
    let mut encoder = LtEncoder::new(&payload, block_len, session_id);
    let k = encoder.k();
    let mut decoder = LtDecoder::new(k, block_len, session_id, byte_length);
    let mut rnd = SplitMix32::new(session_id);
    let mut seq = 0u32;
    let ceiling = (k * 80 + 5000) as u32;
    while !decoder.is_complete() && seq < ceiling {
        let u = rnd.next_u32() as f64 / 4_294_967_296.0;
        if u >= drop_rate {
            decoder.add_frame(seq, &encoder.encode(seq));
        }
        seq += 1;
    }
    RoundTrip {
        overhead: decoder.frames_new() as f64 / k as f64,
        recovered: decoder.assemble(),
    }
}

#[test]
fn payload_survives_the_fountain() {
    for (byte_length, block_len) in [
        (7usize, 2933usize),
        (2933, 2933),
        (50_000, 1445),
        (512 * 1024, 2933),
        (2 * 1024 * 1024, 2933),
    ] {
        let rt = round_trip(byte_length, block_len, 11, 0.0);
        assert_eq!(
            rt.recovered,
            Some(test_payload(byte_length)),
            "{byte_length}B"
        );
    }
}

#[test]
fn deterministic_30_percent_loss_fixture_recovers() {
    let rt = round_trip(512 * 1024, 2933, 23, 0.3);
    assert_eq!(rt.recovered, Some(test_payload(512 * 1024)));
    assert!(rt.overhead < 1.6, "overhead {:.2} too high", rt.overhead);
}

#[test]
fn duplicates_are_counted_but_harmless() {
    let byte_length = 60_000;
    let payload = test_payload(byte_length);
    let mut encoder = LtEncoder::new(&payload, 1445, 31);
    let mut decoder = LtDecoder::new(encoder.k(), 1445, 31, byte_length);
    let mut seq = 0u32;
    while !decoder.is_complete() {
        let frame = encoder.encode(seq);
        decoder.add_frame(seq, &frame);
        decoder.add_frame(seq, &frame);
        seq += 1;
    }
    assert!(decoder.frames_dup() >= decoder.frames_new() - 1);
    assert_eq!(decoder.assemble(), Some(payload));
}

#[test]
fn session_end_to_end_with_loss() {
    let original = b"decimen optical transfer\n".repeat(2000);
    let packed = pack_file("notes.txt", "text/plain", &original).expect("pack");
    assert_eq!(packed.compression, Compression::Gzip);
    let mut sender = Sender::from_packed(&packed, 1465, 0x0c_d1);
    let mut receiver = Receiver::new();
    let mut rnd = SplitMix32::new(0xdead_beef);
    let mut recovered = None;
    for _ in 0..sender.k() as usize * 80 {
        if rnd.next_u32() as f64 / 4_294_967_296.0 >= 0.15 {
            let frame = sender.next_frame();
            if let Some(container) = receiver.push(&frame.to_bytes()) {
                recovered = Some(container);
                break;
            }
        }
    }
    let container = recovered.expect("stream completed");
    assert_eq!(container, packed.container);
    let file = unpack_file(&container).expect("unpack");
    assert_eq!(file.name, "notes.txt");
    assert_eq!(file.mime_type, "text/plain");
    assert_eq!(file.bytes, original);
    assert!(verify_file(&file));
}

#[test]
fn receiver_rejects_foreign_stream_without_losing_progress() {
    let payload = test_payload(20_000);
    let mut a = Sender::new(&payload, 1445, 0x1111);
    let mut b = Sender::new(&payload, 1445, 0x2222);
    let mut receiver = Receiver::new();
    let _ = receiver.push(&a.next_frame().to_bytes());
    assert!(receiver.is_active());
    assert!(matches!(
        receiver.try_push(&b.next_frame().to_bytes()),
        Err(Error::StreamConflict)
    ));
    let mut out = None;
    for _ in 0..200 {
        if let Some(c) = receiver.push(&a.next_frame().to_bytes()) {
            out = Some(c);
            break;
        }
    }
    assert_eq!(out, Some(payload));
}

#[test]
fn corrupted_frame_is_rejected_before_dedup_and_can_be_retransmitted() {
    let payload = test_payload(40_000);
    let mut sender = Sender::new(&payload, 1445, 0x3333);
    let mut receiver = Receiver::new();

    let first = sender.next_frame().to_bytes();
    assert!(receiver.try_push(&first).unwrap().is_none());
    let second = sender.next_frame().to_bytes();
    let mut damaged = second.clone();
    *damaged.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        receiver.try_push(&damaged),
        Err(Error::CorruptFrame)
    ));
    let mut damaged_header = second.clone();
    damaged_header[5] ^= 0x40;
    assert!(matches!(
        receiver.try_push(&damaged_header),
        Err(Error::CorruptFrame)
    ));
    assert!(receiver.try_push(&second).unwrap().is_none());

    let mut recovered = None;
    for _ in 0..sender.k() as usize * 20 {
        if let Some(bytes) = receiver.try_push(&sender.next_frame().to_bytes()).unwrap() {
            recovered = Some(bytes);
            break;
        }
    }
    assert_eq!(recovered, Some(payload));
}

#[test]
fn sender_checked_constructors_reject_invalid_boundaries() {
    assert!(matches!(Sender::try_new(&[], 1445, 1), Err(Error::Empty)));
    assert!(matches!(
        Sender::try_new(&[1], 0, 1),
        Err(Error::InvalidStream)
    ));
    assert!(matches!(
        Sender::try_new(&[1], u16::MAX as usize + 1, 1),
        Err(Error::InvalidStream)
    ));
}

#[test]
fn container_round_trips() {
    let source = b"decimen optical transfer\n".repeat(4000);
    let packed = pack_file("notes.txt", "text/plain", &source).unwrap();
    assert_eq!(packed.compression, Compression::Gzip);
    let recovered = unpack_file(&packed.container).unwrap();
    assert_eq!(recovered.bytes, source);
    assert!(verify_file(&recovered));

    let source2: Vec<u8> = (0..4096)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761u32) >> 24)
        .map(|v| v as u8)
        .collect();
    let packed2 = pack_file("photo.jpg", "image/jpeg", &source2).unwrap();
    assert_eq!(packed2.compression, Compression::None);
    assert_eq!(unpack_file(&packed2.container).unwrap().bytes, source2);
}

#[test]
fn container_rejects_malformed_input() {
    let source = b"bounded output\n".repeat(1000);
    let packed = pack_file("bounded.txt", "text/plain", &source).unwrap();
    let mut malformed = packed.container.clone();
    let orig = source.len() as u32;
    malformed[9..13].copy_from_slice(&(orig + 1).to_le_bytes());
    assert!(matches!(unpack_file(&malformed), Err(Error::GzipSize)));

    let raw = pack_file("raw.bin", "image/jpeg", &[0xa5; 128]).unwrap();
    let mut wrong_plain_len = raw.container;
    wrong_plain_len[9..13].copy_from_slice(&129u32.to_le_bytes());
    assert!(matches!(unpack_file(&wrong_plain_len), Err(Error::Lengths)));

    assert!(matches!(unpack_file(&[0u8; 10]), Err(Error::Truncated)));
    assert!(matches!(unpack_file(&[0u8; 73]), Err(Error::BadMagic)));
}

#[test]
fn names_are_sanitised() {
    let cases: [(&str, &str); 8] = [
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\System32\\drivers\\etc\\hosts", "hosts"),
        ("茅vidence.pdf", "茅vidence.pdf"),
        ("report v2 (final).tar.gz", "report v2 (final).tar.gz"),
        ("CON", "_CON"),
        ("com1.txt", "_com1.txt"),
        ("bad:name?.txt", "bad_name_.txt"),
        ("safe\u{202e}fdp.exe", "safefdp.exe"),
    ];
    for (sent, expected) in cases {
        let packed = pack_file(sent, "application/octet-stream", &[1, 2, 3]).unwrap();
        assert_eq!(unpack_file(&packed.container).unwrap().name, expected);
    }
    for sent in ["..", ".", "/", "   ", "\u{0}\u{7}"] {
        let packed = pack_file(sent, "application/octet-stream", &[1]).unwrap();
        assert_eq!(unpack_file(&packed.container).unwrap().name, "transfer.bin");
    }
}

#[test]
fn mime_metadata_is_validated_on_pack_and_unpack() {
    assert!(matches!(
        pack_file("x", "text/plain\r\nX-Injected: yes", b"x"),
        Err(Error::Meta)
    ));
    assert!(matches!(
        pack_file("x", "not-a-media-type", b"x"),
        Err(Error::Meta)
    ));

    let mut packed = pack_file("x", "text/plain", b"x").unwrap().container;
    // DCF3 fixed header is followed by name then media type. Metadata is not
    // covered by the plain-container digest, so parsing must validate it.
    let name_len = u16::from_le_bytes([packed[5], packed[6]]) as usize;
    packed[deopti_transfer::FILE_HEADER_LEN + name_len] = 0xff;
    assert!(matches!(unpack_file(&packed), Err(Error::Meta)));
}

#[test]
fn compression_decision() {
    for ty in [
        "image/jpeg",
        "image/png",
        "video/mp4",
        "audio/mpeg",
        "application/zip",
        "application/gzip",
        "application/x-7z-compressed",
        "application/epub+zip",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "IMAGE/JPEG",
        "image/jpeg; charset=binary",
    ] {
        assert!(is_precompressed_type(ty), "{ty}");
    }
    for ty in [
        "text/plain",
        "application/json",
        "application/pdf",
        "application/octet-stream",
        "image/svg+xml",
        "image/bmp",
        "audio/wav",
        "",
    ] {
        assert!(!is_precompressed_type(ty), "{ty}");
    }
}

#[test]
fn try_new_rejects_inconsistent_stream_headers() {
    use deopti_transfer::Error;
    assert!(LtDecoder::try_new(0, 2933, 1, 100).is_err());
    assert!(LtDecoder::try_new(10, 0, 1, 100).is_err());
    assert!(LtDecoder::try_new(10, 2933, 1, 0).is_err());
    assert!(
        LtDecoder::try_new(9, 2933, 1, 100).is_err(),
        "k must equal ceil(total/block)"
    );
    assert!(
        LtDecoder::try_new(10, 2933, 1, 100).is_err(),
        "ceil(100/2933)=1 != 10"
    );
    assert!(
        LtDecoder::try_new(1, 2933, 1, 100).is_ok(),
        "single block holds a small payload"
    );
    assert!(LtDecoder::try_new(10, 2933, 1, 29_330).is_ok());
    assert!(LtDecoder::try_new(2, 2933, 1, 2933).is_err());
    assert!(LtDecoder::try_new(2, 2933, 1, 2934).is_ok());
    let oversized = deopti_transfer::MAX_STREAM_BYTES as usize + 1;
    assert!(LtDecoder::try_new(oversized.div_ceil(2933), 2933, 1, oversized).is_err());
    assert!(matches!(
        LtDecoder::try_new(oversized.div_ceil(2933), 2933, 1, oversized),
        Err(Error::TooLarge { .. })
    ));
}

#[test]
fn receiver_ignores_crafted_amplification_frames() {
    use deopti_transfer::frame::{checksum32, frame_checksum, pack_frame, FrameHeader};
    let mut receiver = Receiver::new();
    let block = vec![0u8; 2933];
    let mut header = FrameHeader {
        flags: 0,
        session_id: 0x0c_d1,
        seq: 0,
        k: 65535,
        block_len: 2933,
        total_len: 100,
        stream_tag: checksum32(&[0]),
        frame_tag: 0,
    };
    header.frame_tag = frame_checksum(&header, &block);
    let wire = pack_frame(&header, &block);
    assert!(
        receiver.push(&wire).is_none(),
        "inconsistent k must not create a decoder"
    );
    assert!(!receiver.is_active());

    header.k = 22_900;
    header.total_len = 0xffff_ffff;
    header.frame_tag = frame_checksum(&header, &block);
    let huge = pack_frame(&header, &block);
    assert!(
        receiver.push(&huge).is_none(),
        "oversized total_len must be rejected"
    );
    assert!(!receiver.is_active());
}

#[test]
fn receiver_applies_configured_limits_before_allocating() {
    let payload = test_payload(4096);
    let mut sender = Sender::new(&payload, 512, 0x4242);
    let frame = sender.next_frame().to_bytes();
    let mut receiver = Receiver::with_limits(ReceiverLimits {
        max_stream_bytes: 1024,
        max_source_blocks: 4,
        max_block_len: 256,
    });
    assert!(matches!(
        receiver.try_push(&frame),
        Err(Error::ResourceLimit)
    ));
    assert!(!receiver.is_active());
}

#[test]
fn normal_decode_drops_no_frames() {
    let payload = test_payload(300_000);
    let mut encoder = LtEncoder::new(&payload, 1445, 55);
    let mut decoder = LtDecoder::new(encoder.k(), 1445, 55, 300_000);
    let mut seq = 0u32;
    while !decoder.is_complete() && seq < 20_000 {
        decoder.add_frame(seq, &encoder.encode(seq));
        seq += 1;
    }
    assert_eq!(decoder.assemble(), Some(payload));
    assert_eq!(decoder.frames_dropped(), 0);
}

#[test]
fn systematic_phase_completes_in_exactly_k_frames() {
    let byte_length = 512 * 1024;
    let block_len = 2933;
    let payload = test_payload(byte_length);
    let mut encoder = LtEncoder::new_systematic(&payload, block_len, 9);
    let k = encoder.k();
    assert!(k > 1);
    let mut decoder = LtDecoder::new_systematic(k, block_len, 9, byte_length);
    for seq in 0..k as u32 {
        decoder.add_frame(seq, &encoder.encode(seq));
        assert_eq!(decoder.frames_new(), (seq + 1) as usize);
    }
    assert!(
        decoder.is_complete(),
        "systematic phase must solve every block"
    );
    assert_eq!(decoder.assemble(), Some(payload));
}

#[test]
fn causal_phase_completes_in_exactly_k_frames_in_reverse_order() {
    let byte_length = 512 * 1024;
    let block_len = 2933;
    let payload = test_payload(byte_length);
    let mut encoder = LtEncoder::new_causal(&payload, block_len, 9);
    let k = encoder.k();
    let mut decoder = LtDecoder::new_causal(k, block_len, 9, byte_length);
    for seq in (0..k as u32).rev() {
        decoder.add_frame(seq, &encoder.encode(seq));
    }
    assert!(decoder.is_complete());
    assert_eq!(decoder.frames_new(), k);
    assert_eq!(decoder.assemble(), Some(payload));
}

#[test]
fn causal_phase_turns_a_missing_frame_into_a_repairable_cut() {
    let block_len = 1024;
    let payload = test_payload(block_len * 64);
    let mut encoder = LtEncoder::new_causal(&payload, block_len, 91);
    let k = encoder.k();
    let mut decoder = LtDecoder::new_causal(k, block_len, 91, payload.len());

    for seq in 0..k as u32 {
        if seq != 17 {
            decoder.add_frame(seq, &encoder.encode(seq));
        }
    }
    assert!(!decoder.is_complete());
    for seq in k as u32..k as u32 + 256 {
        decoder.add_frame(seq, &encoder.encode(seq));
        if decoder.is_complete() {
            break;
        }
    }
    assert_eq!(decoder.assemble(), Some(payload));
}

#[test]
fn systematic_phase_survives_loss() {
    let byte_length = 100_000;
    let block_len = 1445;
    let payload = test_payload(byte_length);
    let mut encoder = LtEncoder::new_systematic(&payload, block_len, 23);
    let k = encoder.k();
    let mut decoder = LtDecoder::new_systematic(k, block_len, 23, byte_length);
    let mut rnd = SplitMix32::new(0x5eed);
    let mut seq = 0u32;
    let ceiling = (k * 80 + 5000) as u32;
    while !decoder.is_complete() && seq < ceiling {
        let u = rnd.next_u32() as f64 / 4_294_967_296.0;
        if u >= 0.3 {
            decoder.add_frame(seq, &encoder.encode(seq));
        }
        seq += 1;
    }
    assert_eq!(decoder.assemble(), Some(payload));
    assert!((decoder.frames_new() as f64 / k as f64) < 1.6);
}

#[test]
fn receiver_locking_on_after_systematic_phase_still_decodes() {
    let byte_length = 100_000;
    let block_len = 1445;
    let payload = test_payload(byte_length);
    let mut encoder = LtEncoder::new_systematic(&payload, block_len, 77);
    let k = encoder.k();
    let mut decoder = LtDecoder::new_systematic(k, block_len, 77, byte_length);
    let mut seq = k as u32;
    let ceiling = (k as u32) * 80 + 5000;
    while !decoder.is_complete() && seq < ceiling {
        decoder.add_frame(seq, &encoder.encode(seq));
        seq += 1;
    }
    assert!(decoder.is_complete(), "coded phase alone must complete");
    assert_eq!(decoder.assemble(), Some(payload));
}

#[test]
fn systematic_reduces_frames_needed_under_loss() {
    // Per-seq deterministic drop mask: all decoders see identical drops per seq.
    let drop = |seq: u32, rate: f64| {
        let u = SplitMix32::new(seq ^ 0x5eed_1234).next_u32() as f64 / 4_294_967_296.0;
        u < rate
    };
    let byte_length = 200_000;
    let block_len = 1445;
    let payload = test_payload(byte_length);
    let mut enc_rsd = LtEncoder::new(&payload, block_len, 31337);
    let mut enc_sys = LtEncoder::new_systematic(&payload, block_len, 31337);
    let k = enc_rsd.k();
    assert_eq!(enc_sys.k(), k);
    for &rate in &[0.0f64, 0.1, 0.3] {
        let measure = |encoder: &mut LtEncoder, decoder: &mut LtDecoder| {
            let mut seq = 0u32;
            let ceiling = (k as u32) * 200 + 10_000;
            while !decoder.is_complete() && seq < ceiling {
                if !drop(seq, rate) {
                    decoder.add_frame(seq, &encoder.encode(seq));
                }
                seq += 1;
            }
            assert_eq!(decoder.assemble(), Some(payload.clone()));
            decoder.frames_new()
        };
        let mut pure = LtDecoder::new(k, block_len, 31337, byte_length);
        let pure_frames = measure(&mut enc_rsd, &mut pure);
        let mut sys1 = LtDecoder::new_systematic(k, block_len, 31337, byte_length);
        let sys1_frames = measure(&mut enc_sys, &mut sys1);
        if rate == 0.0 {
            assert_eq!(
                sys1_frames, k,
                "zero-loss single systematic must need exactly k frames"
            );
            assert!(
                sys1_frames <= pure_frames,
                "systematic must beat pure RSD at zero loss"
            );
        } else {
            assert!(
                (sys1_frames as f64) < k as f64 * 1.6,
                "systematic decode must still complete"
            );
        }
        println!(
            "overhead rate={:.0}% pure={:.3} sys1={:.3}",
            rate * 100.0,
            pure_frames as f64 / k as f64,
            sys1_frames as f64 / k as f64,
        );
    }
}

#[test]
fn causal_overhead_stays_below_fixture_threshold() {
    let drop = |seq: u32, rate: f64| {
        let u = SplitMix32::new(seq ^ 0x5eed_1234).next_u32() as f64 / 4_294_967_296.0;
        u < rate
    };
    let byte_length = 200_000;
    let block_len = 1445;
    let payload = test_payload(byte_length);
    let mut encoder = LtEncoder::new_causal(&payload, block_len, 31337);
    let k = encoder.k();
    for &rate in &[0.0f64, 0.1, 0.3] {
        let mut decoder = LtDecoder::new_causal(k, block_len, 31337, byte_length);
        let mut seq = 0u32;
        while !decoder.is_complete() && seq < (k as u32) * 200 + 10_000 {
            if !drop(seq, rate) {
                decoder.add_frame(seq, &encoder.encode(seq));
            }
            seq += 1;
        }
        assert_eq!(decoder.assemble(), Some(payload.clone()));
        let overhead = decoder.frames_new() as f64 / k as f64;
        assert!(overhead < 1.6, "rate={rate} overhead={overhead}");
        println!(
            "causal overhead rate={:.0}% value={overhead:.3}",
            rate * 100.0
        );
    }
}

#[cfg(feature = "encryption")]
#[test]
fn encrypted_container_round_trips_and_verifies() {
    use deopti_transfer::container::pack_file_encrypted;
    use deopti_transfer::container::unpack_file_with_key;
    use deopti_transfer::crypto::EncryptionKey;
    let nonce = [0x42u8; 24];
    let key = EncryptionKey::from_password(b"correct horse battery staple", &nonce).unwrap();
    let source = b"decimen optical transfer\n".repeat(4000);
    let packed = pack_file_encrypted("notes.txt", "text/plain", &source, &key, &nonce).unwrap();
    assert!(packed.encrypted);
    let file = unpack_file_with_key(&packed.container, &key).unwrap();
    assert!(file.encrypted);
    assert_eq!(file.name, "notes.txt");
    assert_eq!(file.bytes, source);
    assert!(verify_file(&file));
}

#[cfg(feature = "encryption")]
#[test]
fn encrypted_container_rejects_wrong_key_and_tampering() {
    use deopti_transfer::container::{pack_file_encrypted, unpack_file_with_key};
    use deopti_transfer::crypto::EncryptionKey;
    let nonce = [0x42u8; 24];
    let key = EncryptionKey::from_password(b"correct horse battery staple", &nonce).unwrap();
    let wrong = EncryptionKey::from_password(b"wrong password", &nonce).unwrap();
    let source = b"top secret payload\n".repeat(1000);
    let packed = pack_file_encrypted("secret.txt", "text/plain", &source, &key, &nonce).unwrap();
    assert!(matches!(
        unpack_file_with_key(&packed.container, &wrong),
        Err(Error::Crypto)
    ));

    let mut tampered = packed.container.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xff;
    assert!(matches!(
        unpack_file_with_key(&tampered, &key),
        Err(Error::Crypto)
    ));
}

#[cfg(feature = "encryption")]
#[test]
fn encrypted_container_without_key_is_rejected() {
    use deopti_transfer::container::pack_file_encrypted;
    use deopti_transfer::crypto::EncryptionKey;
    let nonce = [1u8; 24];
    let key = EncryptionKey::from_password(b"secret", &nonce).unwrap();
    let packed = pack_file_encrypted("s.txt", "text/plain", b"data", &key, &nonce).unwrap();
    assert!(matches!(
        unpack_file(&packed.container),
        Err(Error::NoEncryption)
    ));
}

#[cfg(feature = "encryption")]
#[test]
fn password_api_derives_per_container_key_and_round_trips() {
    use deopti_transfer::container::{
        pack_file_encrypted_with_password, unpack_file_with_password,
    };
    let nonce = [0x5au8; 24];
    let packed = pack_file_encrypted_with_password(
        "private.bin",
        "application/octet-stream",
        b"password protected",
        b"correct horse battery staple",
        &nonce,
    )
    .unwrap();
    let file =
        unpack_file_with_password(&packed.container, b"correct horse battery staple").unwrap();
    assert_eq!(file.bytes, b"password protected");
    assert!(unpack_file_with_password(&packed.container, b"wrong password").is_err());
}

#[cfg(feature = "encryption")]
#[test]
fn jrc_container_round_trips_through_the_fountain() {
    use deopti_transfer::container::{pack_file_jrc, unpack_file_jrc};
    use deopti_transfer::jrc::keygen;
    let kp = keygen().unwrap();
    let source = b"judge-recoverable optical payload\n".repeat(3000);
    let nonce = [0x42u8; 24];
    let packed = pack_file_jrc("report.pdf", "application/pdf", &source, &kp.ek, &nonce).unwrap();

    // The JRC envelope flows through the fountain exactly like a container:
    // no handshake, the receiver reconstructs the opaque envelope bytes.
    let mut sender = Sender::try_new(&packed.envelope, 1465, 0x0c_d1).unwrap();
    let mut receiver = Receiver::new();
    let mut envelope = None;
    for _ in 0..sender.k() as usize * 4 {
        let frame = sender.try_next_frame().unwrap();
        if let Some(container) = receiver.try_push(&frame.to_bytes()).unwrap() {
            envelope = Some(container);
            break;
        }
    }
    let envelope = envelope.expect("stream completed");

    // External hiding: the reconstructed envelope never contains the
    // plaintext payload.
    assert!(!envelope.windows(source.len()).any(|w| w == &source[..]));

    // The designated judge recovers and verifies the file end to end.
    let file = unpack_file_jrc(&envelope, &kp.dk).unwrap();
    assert_eq!(file.name, "report.pdf");
    assert_eq!(file.mime_type, "application/pdf");
    assert_eq!(file.bytes, source);
    assert!(verify_file(&file));
}

#[cfg(feature = "encryption")]
#[test]
fn jrc_container_rejects_wrong_judge_and_tampering() {
    use deopti_transfer::container::{pack_file_jrc, unpack_file_jrc};
    use deopti_transfer::jrc::keygen;
    let kp_a = keygen().unwrap();
    let kp_b = keygen().unwrap();
    let source = b"top secret\n".repeat(1000);
    let nonce = [0x42u8; 24];
    let packed = pack_file_jrc("s.txt", "text/plain", &source, &kp_a.ek, &nonce).unwrap();

    // Judge-only recoverability: the wrong judge's key cannot recover.
    assert!(matches!(
        unpack_file_jrc(&packed.envelope, &kp_b.dk),
        Err(Error::Crypto)
    ));

    // A single flipped byte anywhere is rejected (AEAD tag + DCF3 digest).
    let mut tampered = packed.envelope.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xff;
    assert!(unpack_file_jrc(&tampered, &kp_a.dk).is_err());

    // Truncation is rejected.
    assert!(unpack_file_jrc(&packed.envelope[..packed.envelope.len() - 1], &kp_a.dk).is_err());

    // A plain (non-JRC) DCF3 container is rejected on envelope parsing.
    let plain = pack_file("p.txt", "text/plain", b"x").unwrap();
    assert!(unpack_file_jrc(&plain.container, &kp_a.dk).is_err());
}
