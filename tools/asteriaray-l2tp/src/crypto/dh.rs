use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;

pub const DH_GROUP2_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

pub const DH_GROUP14_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhGroup {
    Group2 = 2,
    Group14 = 14,
}

pub struct DhExchange {
    pub group: DhGroup,
    pub prime: BigUint,
    pub generator: BigUint,
    private_key: BigUint,
    pub public_key: BigUint,
    pub byte_len: usize,
}

impl DhExchange {
    pub fn new(group: DhGroup) -> Self {
        let (hex, byte_len) = match group {
            DhGroup::Group2 => (DH_GROUP2_HEX, 128),
            DhGroup::Group14 => (DH_GROUP14_HEX, 256),
        };
        let prime = BigUint::parse_bytes(hex.as_bytes(), 16).expect("invalid DH prime hex");
        let generator = BigUint::from(2u32);

        let mut rng = OsRng;
        let private_key = rng.gen_biguint((byte_len * 8 - 1) as u64);
        let public_key = generator.modpow(&private_key, &prime);

        Self {
            group,
            prime,
            generator,
            private_key,
            public_key,
            byte_len,
        }
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        let b = self.public_key.to_bytes_be();
        if b.len() < self.byte_len {
            let mut padded = vec![0u8; self.byte_len - b.len()];
            padded.extend_from_slice(&b);
            padded
        } else if b.len() > self.byte_len {
            b[b.len() - self.byte_len..].to_vec()
        } else {
            b
        }
    }

    pub fn compute_shared_secret(&self, peer_public_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        let peer_pub = BigUint::from_bytes_be(peer_public_bytes);
        if peer_pub <= BigUint::from(1u32) || peer_pub >= self.prime {
            return Err("invalid peer DH public key");
        }
        let shared = peer_pub.modpow(&self.private_key, &self.prime);
        let b = shared.to_bytes_be();
        if b.len() < self.byte_len {
            let mut padded = vec![0u8; self.byte_len - b.len()];
            padded.extend_from_slice(&b);
            Ok(padded)
        } else if b.len() > self.byte_len {
            Ok(b[b.len() - self.byte_len..].to_vec())
        } else {
            Ok(b)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_exchange_group2() {
        let alice = DhExchange::new(DhGroup::Group2);
        let bob = DhExchange::new(DhGroup::Group2);

        let alice_pub = alice.public_bytes();
        let bob_pub = bob.public_bytes();

        let s1 = alice.compute_shared_secret(&bob_pub).unwrap();
        let s2 = bob.compute_shared_secret(&alice_pub).unwrap();

        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 128);
    }
}
