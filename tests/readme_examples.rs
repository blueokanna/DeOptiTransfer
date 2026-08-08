use deopti_transfer::container::{pack_file, unpack_file};
use deopti_transfer::session::{Receiver, Sender};

#[test]
fn readme_plain_transfer_example() {
    let packed = pack_file("notes.txt", "text/plain", b"hello over light").unwrap();
    let mut sender = Sender::try_from_packed(&packed, 1465, 0x0c_d1).unwrap();
    let mut receiver = Receiver::new();
    let mut recovered = None;
    for _ in 0..sender.k() as usize * 4 {
        let frame = sender.try_next_frame().unwrap();
        if let Some(container) = receiver.try_push(&frame.to_bytes()).unwrap() {
            recovered = Some(container);
            break;
        }
    }
    let file = unpack_file(&recovered.expect("stream completed")).unwrap();
    assert_eq!(file.bytes, b"hello over light");
}

#[cfg(feature = "encryption")]
#[test]
fn readme_encrypted_transfer_example() {
    use deopti_transfer::container::unpack_file_with_password;
    use deopti_transfer::crypto::random_nonce;

    let nonce = random_nonce().unwrap();
    let packed = deopti_transfer::pack_file_encrypted_with_password(
        "secret.txt",
        "text/plain",
        b"top secret",
        b"correct horse battery staple",
        &nonce,
    )
    .unwrap();
    let file = unpack_file_with_password(&packed.container, b"correct horse battery staple").unwrap();
    assert_eq!(file.bytes, b"top secret");
}
