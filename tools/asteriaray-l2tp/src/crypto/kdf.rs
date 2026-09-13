use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

pub fn prf(alg: HashAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlgorithm::Md5 => {
            let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

pub struct Ikev1Keys {
    pub skeyid: Vec<u8>,
    pub skeyid_d: Vec<u8>,
    pub skeyid_a: Vec<u8>,
    pub skeyid_e: Vec<u8>,
}

impl Ikev1Keys {
    pub fn derive(
        alg: HashAlgorithm,
        psk: &[u8],
        nonce_i: &[u8],
        nonce_r: &[u8],
        shared_secret: &[u8],
        cky_i: &[u8; 8],
        cky_r: &[u8; 8],
    ) -> Self {
        // SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
        let mut skeyid_in = Vec::with_capacity(nonce_i.len() + nonce_r.len());
        skeyid_in.extend_from_slice(nonce_i);
        skeyid_in.extend_from_slice(nonce_r);
        let skeyid = prf(alg, psk, &skeyid_in);

        // SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
        let mut d_in = Vec::with_capacity(shared_secret.len() + 16 + 1);
        d_in.extend_from_slice(shared_secret);
        d_in.extend_from_slice(cky_i);
        d_in.extend_from_slice(cky_r);
        d_in.push(0);
        let skeyid_d = prf(alg, &skeyid, &d_in);

        // SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
        let mut a_in = Vec::with_capacity(skeyid_d.len() + shared_secret.len() + 16 + 1);
        a_in.extend_from_slice(&skeyid_d);
        a_in.extend_from_slice(shared_secret);
        a_in.extend_from_slice(cky_i);
        a_in.extend_from_slice(cky_r);
        a_in.push(1);
        let skeyid_a = prf(alg, &skeyid, &a_in);

        // SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
        let mut e_in = Vec::with_capacity(skeyid_a.len() + shared_secret.len() + 16 + 1);
        e_in.extend_from_slice(&skeyid_a);
        e_in.extend_from_slice(shared_secret);
        e_in.extend_from_slice(cky_i);
        e_in.extend_from_slice(cky_r);
        e_in.push(2);
        let skeyid_e = prf(alg, &skeyid, &e_in);

        Self {
            skeyid,
            skeyid_d,
            skeyid_a,
            skeyid_e,
        }
    }

    pub fn compute_hash_i(
        &self,
        alg: HashAlgorithm,
        g_xi: &[u8],
        g_xr: &[u8],
        cky_i: &[u8; 8],
        cky_r: &[u8; 8],
        sa_b: &[u8],
        id_i_b: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(g_xi.len() + g_xr.len() + 16 + sa_b.len() + id_i_b.len());
        data.extend_from_slice(g_xi);
        data.extend_from_slice(g_xr);
        data.extend_from_slice(cky_i);
        data.extend_from_slice(cky_r);
        data.extend_from_slice(sa_b);
        data.extend_from_slice(id_i_b);
        prf(alg, &self.skeyid_a, &data)
    }

    pub fn compute_nat_d(
        alg: HashAlgorithm,
        skeyid_a: &[u8],
        cky_i: &[u8; 8],
        cky_r: &[u8; 8],
        ip: &[u8],
        port: u16,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(16 + ip.len() + 2);
        data.extend_from_slice(cky_i);
        data.extend_from_slice(cky_r);
        data.extend_from_slice(ip);
        data.extend_from_slice(&port.to_be_bytes());
        prf(alg, skeyid_a, &data)
    }

    pub fn expand_keymat(
        alg: HashAlgorithm,
        skeyid_d: &[u8],
        protocol: u8,
        spi: &[u8],
        nonce_i: &[u8],
        nonce_r: &[u8],
        needed_len: usize,
    ) -> Vec<u8> {
        let mut keymat = Vec::new();
        let mut prev_k = Vec::new();

        while keymat.len() < needed_len {
            let mut data = Vec::new();
            if !prev_k.is_empty() {
                data.extend_from_slice(&prev_k);
            }
            data.push(protocol);
            data.extend_from_slice(spi);
            data.extend_from_slice(nonce_i);
            data.extend_from_slice(nonce_r);

            prev_k = prf(alg, skeyid_d, &data);
            keymat.extend_from_slice(&prev_k);
        }

        keymat.truncate(needed_len);
        keymat
    }
}
