use der::{DecodePem, EncodeValue};
use x509_cert::Certificate;

use crate::cert::load::Encoding;

pub(super) trait Encode {
    fn encode(self, encoding: Encoding) -> Vec<u8>;
}

impl Encode for String {
    fn encode(self, encoding: Encoding) -> Vec<u8> {
        match encoding {
            Encoding::PEM => self.into_bytes(),
            Encoding::DER => {
                let cert = Certificate::from_pem(dbg!(self).as_bytes())
                    .expect("ACME client should return valid PEM");
                let mut writer = Vec::new();
                cert.encode_value(&mut writer)
                    .expect("Encoding certificate to a vec never gives IO issues");
                writer
            }
        }
    }
}

impl Encode for Vec<String> {
    fn encode(self, encoding: Encoding) -> Vec<u8> {
        match encoding {
            Encoding::PEM => self.into_iter().flat_map(String::into_bytes).collect(),
            Encoding::DER => unreachable!("der does not support encoding multiple items"),
        }
    }
}
