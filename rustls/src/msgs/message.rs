use crate::enums::ProtocolVersion;
use crate::enums::{AlertDescription, ContentType, HandshakeType};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::internal::record_layer::RecordLayer;
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{u48, Codec, Reader, ReaderMut};
use crate::msgs::enums::AlertLevel;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::handshake::HandshakeMessagePayload;

use crate::msgs::message::sealed::Sealed;
use alloc::vec::Vec;
use core::fmt;

use super::base::BorrowedPayload;

#[derive(Debug)]
pub enum MessagePayload<'a> {
    Alert(AlertMessagePayload),
    Handshake {
        parsed: HandshakeMessagePayload<'a>,
        encoded: Payload<'a>,
    },
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Alert(x) => x.encode(bytes),
            Self::Handshake { encoded, .. } => bytes.extend(encoded.bytes()),
            Self::ChangeCipherSpec(x) => x.encode(bytes),
            Self::ApplicationData(x) => x.encode(bytes),
        }
    }

    pub fn handshake(parsed: HandshakeMessagePayload<'a>) -> Self {
        Self::Handshake {
            encoded: Payload::new(parsed.get_encoding()),
            parsed,
        }
    }

    pub fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: &'a [u8],
    ) -> Result<Self, InvalidMessage> {
        let mut r = Reader::init(payload);
        match typ {
            ContentType::ApplicationData => Ok(Self::ApplicationData(Payload::Borrowed(payload))),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakeMessagePayload::read_version(&mut r, vers).map(|parsed| Self::Handshake {
                    parsed,
                    encoded: Payload::Borrowed(payload),
                })
            }
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            _ => Err(InvalidMessage::InvalidContentType),
        }
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Alert(_) => ContentType::Alert,
            Self::Handshake { .. } => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub(crate) fn into_owned(self) -> MessagePayload<'static> {
        use MessagePayload::*;
        match self {
            Alert(x) => Alert(x),
            Handshake { parsed, encoded } => Handshake {
                parsed: parsed.into_owned(),
                encoded: encoded.into_owned(),
            },
            ChangeCipherSpec(x) => ChangeCipherSpec(x),
            ApplicationData(x) => ApplicationData(x.into_owned()),
        }
    }
}

#[derive(Clone, Copy)]
pub struct DtlsEpochSequence(u64);

impl DtlsEpochSequence {
    pub fn new(epoch: u16, sequence: u48) -> Self {
        Self(sequence.0 | ((epoch as u64) << u48::BITS))
    }

    pub fn epoch(self) -> u16 {
        (self.0 >> u48::BITS) as u16
    }

    pub fn sequence(self) -> u48 {
        u48(self.0 & u48::MAX.0)
    }
}

impl fmt::Debug for DtlsEpochSequence {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("DtlsEpochSequence");
        builder.field("epoch", &self.epoch());
        builder.field("sequence", &self.sequence());
        builder.finish()
    }
}

pub trait DtlsExtraFields: for<'a> Codec<'a> + Clone + Copy + Sealed + 'static {
    const SIZE: u16;
}

impl DtlsExtraFields for () {
    const SIZE: u16 = 0;
}

impl DtlsExtraFields for DtlsEpochSequence {
    const SIZE: u16 = 8;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for () {}
    impl Sealed for super::DtlsEpochSequence {}
}

impl Codec<'_> for () {
    fn encode(&self, _: &mut Vec<u8>) {}

    fn read(_: &mut Reader) -> Result<Self, InvalidMessage> {
        Ok(())
    }
}

impl Codec<'_> for DtlsEpochSequence {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        u64::read(r).map(Self)
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type owns all memory for its interior parts. It is used to read/write from/to I/O
/// buffers as well as for fragmenting, joining and encryption/decryption. It can be converted
/// into a `Message` by decoding the payload.
///
/// # Decryption
/// Internally the message payload is stored as a `Vec<u8>`; this can by mutably borrowed with
/// [`OpaqueMessage::payload_mut()`].  This is useful for decrypting a message in-place.
/// After the message is decrypted, call [`OpaqueMessage::into_plain_message()`] or borrow this
/// message and call [`BorrowedOpaqueMessage::into_tls13_unpadded_message`].
#[derive(Clone, Debug)]
pub struct OpaqueMessage<D = ()> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub dtls: D,
    payload: Payload<'static>,
}

impl OpaqueMessage {
    pub fn with_dtls(self, dtls: DtlsEpochSequence) -> OpaqueMessage<DtlsEpochSequence> {
        let Self {
            typ,
            version,
            payload,
            ..
        } = self;
        OpaqueMessage {
            typ,
            version,
            dtls,
            payload,
        }
    }
}

impl<D: DtlsExtraFields> OpaqueMessage<D> {
    /// Construct a new `OpaqueMessage` from constituent fields.
    ///
    /// `body` is moved into the `payload` field.
    pub fn new(typ: ContentType, version: ProtocolVersion, dtls: D, body: Vec<u8>) -> Self {
        Self {
            typ,
            version,
            dtls,
            payload: Payload::new(body),
        }
    }

    /// Access the message payload as a slice.
    pub fn payload(&self) -> &[u8] {
        self.payload.bytes()
    }

    /// Access the message payload as a mutable `Vec<u8>`.
    pub fn payload_mut(&mut self) -> &mut Vec<u8> {
        match &mut self.payload {
            Payload::Borrowed(_) => unreachable!("due to how constructor works"),
            Payload::Owned(bytes) => bytes,
        }
    }

    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader) -> Result<Self, MessageError> {
        let (typ, version, dtls, len) = read_opaque_message_header(r)?;

        let mut sub = r
            .sub(len as usize)
            .map_err(|_| MessageError::TooShortForLength)?;
        let payload = Payload::read(&mut sub).into_owned();

        Ok(Self {
            typ,
            version,
            dtls,
            payload,
        })
    }

    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.typ.encode(&mut buf);
        self.version.encode(&mut buf);
        (self.payload.bytes().len() as u16).encode(&mut buf);
        self.payload.encode(&mut buf);
        buf
    }

    /// Force conversion into a plaintext message.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// `OpaqueMessage` should be decrypted into a `PlainMessage` using a `MessageDecrypter`.
    pub fn into_plain_message(self) -> PlainMessage<D> {
        PlainMessage {
            version: self.version,
            typ: self.typ,
            dtls: self.dtls,
            payload: self.payload,
        }
    }

    #[cfg(test)]
    pub(crate) fn borrow(&mut self) -> BorrowedOpaqueMessage<D> {
        BorrowedOpaqueMessage {
            typ: self.typ,
            version: self.version,
            dtls: self.dtls,
            payload: BorrowedPayload::new(self.payload_mut()),
        }
    }

    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16384 + 2048;

    /// Content type, version, optional dtls fields, and size.
    const HEADER_SIZE: u16 = 1 + 2 + D::SIZE + 2;

    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;
}

/// A borrowed version of [`OpaqueMessage`].
pub struct BorrowedOpaqueMessage<'a, D = ()> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub dtls: D,
    pub payload: BorrowedPayload<'a>,
}

impl<'a, D> BorrowedOpaqueMessage<'a, D> {
    /// Force conversion into a plaintext message.
    ///
    /// See [`OpaqueMessage::into_plain_message`] for more information
    pub fn into_plain_message(self) -> BorrowedPlainMessage<'a, D> {
        BorrowedPlainMessage {
            typ: self.typ,
            version: self.version,
            dtls: self.dtls,
            payload: self.payload.into_inner(),
        }
    }

    /// For TLS1.3 (only), checks the length msg.payload is valid and removes the padding.
    ///
    /// Returns an error if the message (pre-unpadding) is too long, or the padding is invalid,
    /// or the message (post-unpadding) is too long.
    pub fn into_tls13_unpadded_message(mut self) -> Result<BorrowedPlainMessage<'a, D>, Error> {
        let payload = &mut self.payload;

        if payload.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.typ = unpad_tls13_payload(payload);
        if self.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.version = ProtocolVersion::TLSv1_3;
        Ok(self.into_plain_message())
    }
}

impl<'a, D: DtlsExtraFields> BorrowedOpaqueMessage<'a, D> {
    pub(crate) fn read(r: &mut ReaderMut<'a>) -> Result<Self, MessageError> {
        let (typ, version, dtls, len) = r.as_reader(read_opaque_message_header)?;

        let mut sub = r
            .sub(len as usize)
            .map_err(|_| MessageError::TooShortForLength)?;
        let payload = BorrowedPayload::read(&mut sub);

        Ok(Self {
            typ,
            version,
            dtls,
            payload,
        })
    }
}

fn read_opaque_message_header<'a, D: DtlsExtraFields>(
    r: &mut Reader<'a>,
) -> Result<(ContentType, ProtocolVersion, D, u16), MessageError> {
    let typ = ContentType::read(r).map_err(|_| MessageError::TooShortForHeader)?;
    // Don't accept any new content-types.
    if let ContentType::Unknown(_) = typ {
        return Err(MessageError::InvalidContentType);
    }

    let version = ProtocolVersion::read(r).map_err(|_| MessageError::TooShortForHeader)?;
    // Accept only versions 0x03XX for any XX.
    match version {
        ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
            return Err(MessageError::UnknownProtocolVersion);
        }
        _ => {}
    };

    let dtls = D::read(r).map_err(|_| MessageError::TooShortForHeader)?;

    let len = u16::read(r).map_err(|_| MessageError::TooShortForHeader)?;

    // Reject undersize messages
    //  implemented per section 5.1 of RFC8446 (TLSv1.3)
    //              per section 6.2.1 of RFC5246 (TLSv1.2)
    if typ != ContentType::ApplicationData && len == 0 {
        return Err(MessageError::InvalidEmptyPayload);
    }

    // Reject oversize messages
    if len >= OpaqueMessage::<D>::MAX_PAYLOAD {
        return Err(MessageError::MessageTooLarge);
    }

    Ok((typ, version, dtls, len))
}

/// `v` is a message payload, immediately post-decryption.  This function
/// removes zero padding bytes, until a non-zero byte is encountered which is
/// the content type, which is returned.  See RFC8446 s5.2.
///
/// ContentType(0) is returned if the message payload is empty or all zeroes.
fn unpad_tls13_payload(p: &mut BorrowedPayload) -> ContentType {
    loop {
        match p.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

impl<D> From<Message<'_, D>> for PlainMessage<D> {
    fn from(msg: Message<D>) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload.into_owned(),
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                Payload::Owned(buf)
            }
        };

        Self {
            typ,
            version: msg.version,
            dtls: msg.dtls,
            payload,
        }
    }
}

/// A decrypted TLS frame
///
/// This type owns all memory for its interior parts. It can be decrypted from an OpaqueMessage
/// or encrypted into an OpaqueMessage, and it is also used for joining and fragmenting.
#[derive(Clone, Debug)]
pub struct PlainMessage<D = ()> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub dtls: D,
    pub payload: Payload<'static>,
}

impl<D: DtlsExtraFields> PlainMessage<D> {
    pub fn into_unencrypted_opaque(self) -> OpaqueMessage<D> {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            dtls: self.dtls,
            payload: self.payload,
        }
    }

    pub fn borrow(&self) -> BorrowedPlainMessage<'_, D> {
        BorrowedPlainMessage {
            version: self.version,
            typ: self.typ,
            dtls: self.dtls,
            payload: self.payload.bytes(),
        }
    }
}

/// A message with decoded payload
#[derive(Debug)]
pub struct Message<'a, D = ()> {
    pub version: ProtocolVersion,
    pub dtls: D,
    pub payload: MessagePayload<'a>,
}

impl<D: DtlsExtraFields> Message<'_, D> {
    pub fn is_handshake_type(&self, hstyp: HandshakeType) -> bool {
        // Bit of a layering violation, but OK.
        if let MessagePayload::Handshake { parsed, .. } = &self.payload {
            parsed.typ == hstyp
        } else {
            false
        }
    }

    pub(crate) fn into_owned(self) -> Message<'static, D> {
        let Self { version, dtls, .. } = self;
        Message {
            version,
            dtls,
            payload: self.payload.into_owned(),
        }
    }
}

impl Message<'_> {
    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Self {
        Self {
            version: ProtocolVersion::TLSv1_2,
            dtls: (),
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            dtls: (),
            payload: MessagePayload::handshake(HandshakeMessagePayload::build_key_update_notify()),
        }
    }
}

impl<D> TryFrom<PlainMessage<D>> for Message<'static, D> {
    type Error = Error;

    fn try_from(plain: PlainMessage<D>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            dtls: plain.dtls,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload.bytes())?
                .into_owned(),
        })
    }
}

/// Parses a plaintext message into a well-typed [`Message`].
///
/// A [`PlainMessage`] must contain plaintext content. Encrypted content should be stored in an
/// [`OpaqueMessage`] and decrypted before being stored into a [`PlainMessage`].
impl<'a, D> TryFrom<BorrowedPlainMessage<'a, D>> for Message<'a, D> {
    type Error = Error;

    fn try_from(plain: BorrowedPlainMessage<'a, D>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            dtls: plain.dtls,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type differs from `OpaqueMessage` because it borrows
/// its payload.  You can make a `OpaqueMessage` from an
/// `BorrowMessage`, but this involves a copy.
///
/// This type also cannot decode its internals and
/// cannot be read/encoded; only `OpaqueMessage` can do that.
#[derive(Debug)]
pub struct BorrowedPlainMessage<'a, D = ()> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub dtls: D,
    pub payload: &'a [u8],
}

impl<'a, D: DtlsExtraFields> BorrowedPlainMessage<'a, D> {
    pub fn to_unencrypted_opaque(&self) -> OpaqueMessage<D> {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            dtls: self.dtls,
            payload: Payload::Owned(self.payload.to_vec()),
        }
    }

    pub fn encoded_len(&self, record_layer: &RecordLayer) -> usize {
        OpaqueMessage::<D>::HEADER_SIZE as usize + record_layer.encrypted_len(self.payload.len())
    }

    pub fn into_owned(self) -> PlainMessage<D> {
        let Self {
            typ, version, dtls, ..
        } = self;
        PlainMessage {
            typ,
            version,
            dtls,
            payload: Payload::new(self.payload),
        }
    }
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    InvalidEmptyPayload,
    MessageTooLarge,
    InvalidContentType,
    UnknownProtocolVersion,
}
