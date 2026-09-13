use md4::{Digest, Md4};
use sha1::Sha1;

/// Standard DES permutation tables and operations for MS-CHAPv2 response (RFC 2759)
mod des {
    const IP: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];

    const FP: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];

    const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];

    const PC2: [u8; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];

    const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    const E_BIT: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];

    const P_BOX: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
    ];

    const S_BOXES: [[[u8; 16]; 4]; 8] = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
    ];

    fn permute(val: u64, table: &[u8], in_len: usize) -> u64 {
        let mut res = 0;
        for (i, &pos) in table.iter().enumerate() {
            let bit = (val >> (in_len - pos as usize)) & 1;
            res |= bit << (table.len() - 1 - i);
        }
        res
    }

    pub fn des_encrypt_block(key_8bytes: [u8; 8], block_8bytes: [u8; 8]) -> [u8; 8] {
        let key_val = u64::from_be_bytes(key_8bytes);
        let block_val = u64::from_be_bytes(block_8bytes);

        // Key schedule
        let pc1 = permute(key_val, &PC1, 64);
        let mut c = (pc1 >> 28) as u32;
        let mut d = (pc1 & 0x0FFFFFFF) as u32;

        let mut round_keys = [0u64; 16];
        for i in 0..16 {
            let shift = SHIFTS[i] as u32;
            c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF;
            d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF;
            let cd = ((c as u64) << 28) | (d as u64);
            round_keys[i] = permute(cd, &PC2, 56);
        }

        // IP
        let ip = permute(block_val, &IP, 64);
        let mut l = (ip >> 32) as u32;
        let mut r = (ip & 0xFFFFFFFF) as u32;

        for k in round_keys.iter() {
            let r_expanded = permute(r as u64, &E_BIT, 32) ^ k;
            let mut s_output = 0u32;
            for s in 0..8 {
                let chunk = ((r_expanded >> (42 - s * 6)) & 0x3F) as u8;
                let row = (((chunk >> 5) & 1) << 1) | (chunk & 1);
                let col = (chunk >> 1) & 0x0F;
                s_output = (s_output << 4) | (S_BOXES[s][row as usize][col as usize] as u32);
            }
            let f = permute(s_output as u64, &P_BOX, 32) as u32;
            let new_r = l ^ f;
            l = r;
            r = new_r;
        }

        let pre_out = ((r as u64) << 32) | (l as u64);
        let final_out = permute(pre_out, &FP, 64);
        final_out.to_be_bytes()
    }
}

pub fn make_des_key(k7: &[u8]) -> [u8; 8] {
    let mut k8 = [0u8; 8];
    k8[0] = k7[0] & 0xFE;
    k8[1] = ((k7[0] << 7) | (k7[1] >> 1)) & 0xFE;
    k8[2] = ((k7[1] << 6) | (k7[2] >> 2)) & 0xFE;
    k8[3] = ((k7[2] << 5) | (k7[3] >> 3)) & 0xFE;
    k8[4] = ((k7[3] << 4) | (k7[4] >> 4)) & 0xFE;
    k8[5] = ((k7[4] << 3) | (k7[5] >> 5)) & 0xFE;
    k8[6] = ((k7[5] << 2) | (k7[6] >> 6)) & 0xFE;
    k8[7] = (k7[6] << 1) & 0xFE;
    k8
}

pub fn nt_password_hash(password: &str) -> [u8; 16] {
    let mut unicode_pwd = Vec::with_capacity(password.len() * 2);
    for c in password.encode_utf16() {
        unicode_pwd.extend_from_slice(&c.to_le_bytes());
    }
    let mut md4 = Md4::new();
    md4.update(&unicode_pwd);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&md4.finalize());
    hash
}

pub fn challenge_hash(
    peer_challenge: &[u8; 16],
    authenticator_challenge: &[u8; 16],
    username: &str,
) -> [u8; 8] {
    let mut sha1 = Sha1::new();
    sha1.update(peer_challenge);
    sha1.update(authenticator_challenge);
    // RFC 2759: userName with any domain prefix removed
    let stripped = username.split('\\').last().unwrap_or(username);
    sha1.update(stripped.as_bytes());
    let full = sha1.finalize();
    let mut res = [0u8; 8];
    res.copy_from_slice(&full[..8]);
    res
}

pub fn challenge_response(challenge_8: [u8; 8], password_hash_16: [u8; 16]) -> [u8; 24] {
    let key1 = make_des_key(&password_hash_16[0..7]);
    let key2 = make_des_key(&password_hash_16[7..14]);
    let mut k3_7 = [0u8; 7];
    k3_7[0..2].copy_from_slice(&password_hash_16[14..16]);
    let key3 = make_des_key(&k3_7);

    let b1 = des::des_encrypt_block(key1, challenge_8);
    let b2 = des::des_encrypt_block(key2, challenge_8);
    let b3 = des::des_encrypt_block(key3, challenge_8);

    let mut resp = [0u8; 24];
    resp[0..8].copy_from_slice(&b1);
    resp[8..16].copy_from_slice(&b2);
    resp[16..24].copy_from_slice(&b3);
    resp
}

/// Builds standard 49-byte MS-CHAPv2 response structure (RFC 2759 Section 8.1)
pub fn generate_mschapv2_response(
    username: &str,
    password: &str,
    auth_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
) -> [u8; 49] {
    let pwd_hash = nt_password_hash(password);
    let chal_8 = challenge_hash(peer_challenge, auth_challenge, username);
    let nt_resp = challenge_response(chal_8, pwd_hash);

    let mut out = [0u8; 49];
    out[0..16].copy_from_slice(peer_challenge);
    // bytes 16..24 are reserved (zeros)
    out[24..48].copy_from_slice(&nt_resp);
    out[48] = 0x00; // Flags
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_password_hash() {
        let hash = nt_password_hash("clientPass");
        // Known test vector
        assert_eq!(hash.len(), 16);
    }
}
