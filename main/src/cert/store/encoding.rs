use crate::cert::load::Encoding;

pub(super) trait Encode {
    fn encode(self, encoding: Encoding) -> Vec<u8>;
}

impl Encode for String {
    fn encode(self, encoding: Encoding) -> Vec<u8> {
        match encoding {
            Encoding::PEM => self.into_bytes(),
            Encoding::DER => todo!(),
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
