use ark_ec::hashing::HashToCurve;
use ark_ec::CurveGroup;
use sha2::Digest;
use ark_serialize::CanonicalDeserialize;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;

fn main() {
    println!("Hello, world!");
}

fn hash_to_g1(dst:&[u8], msg:&[u8]) -> ark_bls12_381::G1Affine {
    let mapper = ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher::<
        ark_ec::models::short_weierstrass::Projective<ark_bls12_381::g1::Config>,
        ark_ff::fields::field_hashers::DefaultFieldHasher<sha2::Sha256, 128>,
        ark_ec::hashing::curve_maps::wb::WBMap<ark_bls12_381::g1::Config>,
    >::new(dst)
        .unwrap();
    let new_element = <ark_bls12_381::G1Projective>::from(mapper.hash(msg).unwrap());
    new_element.into_affine()
}

fn hash_to_g2(dst:&[u8], msg:&[u8]) -> ark_bls12_381::G2Affine {
    let mapper = ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher::<
        ark_ec::models::short_weierstrass::Projective<ark_bls12_381::g2::Config>,
        ark_ff::fields::field_hashers::DefaultFieldHasher<sha2::Sha256, 128>,
        ark_ec::hashing::curve_maps::wb::WBMap<ark_bls12_381::g2::Config>,
    >::new(dst)
        .unwrap();
    let new_element = <ark_bls12_381::G2Projective>::from(mapper.hash(msg).unwrap());
    new_element.into_affine()
}

fn unchained_msg_to_sign(round: u64) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    let round_bytes = round.to_be_bytes();
    hasher.update(round_bytes);
    let msg = hasher.finalize().to_vec();
    msg
}

fn chained_msg_to_sign(round: u64, prev_sig: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(prev_sig);
    let round_bytes = round.to_be_bytes();
    hasher.update(round_bytes);
    let msg = hasher.finalize().to_vec();
    msg
}

/// From https://drand.love/docs/specification/#cryptographic-specification.
const DST: &[u8; 43] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[test]
fn drand_sig_verify_chained() {
    // Source of the test case: https://drand.love/developer/http-api/#chain-hash-info.
    let prev_sig = hex::decode("859504eade86790ad09b2b3474d5e09d1718b549ef7107d7bbd18f5e221765ce8252d7db02664c1f6b20f40c6e8e138704d2acfeb6c5abcc14c77e3a842b2f84515e7366248ca37b1460d23b4f98493c246fbb02851f2a43a710c968a349f8d6").unwrap();
    let msg = chained_msg_to_sign(367, prev_sig.as_slice());
    let pk_buf = hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31").unwrap();
    let pk = ark_bls12_381::G1Affine::deserialize_compressed(pk_buf.as_slice()).unwrap();
    let msg_hash = hash_to_g2(DST, msg.as_slice());
    let sig_buf = hex::decode("90957ebc0719f8bfb67640aff8ca219bf9f2c5240e60a8711c968d93370d38f87b38ed234a8c63863eb81f234efce55b047478848c0de025527b3d3476dfe860632c1b799550de50a6b9540463e9fb66c8016b89c04a9f52dabdc988e69463c1").unwrap();
    let sig = ark_bls12_381::G2Affine::deserialize_compressed(sig_buf.as_slice()).unwrap();
    assert_eq!(ark_bls12_381::Bls12_381::pairing(pk, msg_hash), ark_bls12_381::Bls12_381::pairing(ark_bls12_381::G1Affine::generator(), sig));
}

#[test]
fn drand_sig_verify_unchained() {
    /*
    Below are the source of the test case.
    '''
    bash-3.2$ curl https://api3.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/info
    {"public_key":"a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e","period":3,"genesis_time":1677685200,"hash":"dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493","groupHash":"a81e9d63f614ccdb144b8ff79fbd4d5a2d22055c0bfe4ee9a8092003dab1c6c0","schemeID":"bls-unchained-on-g1","metadata":{"beaconID":"fastnet"}}
    bash-3.2$ curl https://api3.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/614294
    {"round":614294,"randomness":"b1c2d777e51e53e6817e4ee6e8ab79b2fa8d75ae8c63866ee84303239b25d54e","signature":"b1e0bb6804f576b77d562169a5fab44116711e89a4a8ccbf0c237ef20841880b472ef28ad57fb9da6a507411d5c8a9bf"}
    bash-3.2$
    '''
     */
    let msg = unchained_msg_to_sign(614294);
    let sig_buf = hex::decode("b1e0bb6804f576b77d562169a5fab44116711e89a4a8ccbf0c237ef20841880b472ef28ad57fb9da6a507411d5c8a9bf").unwrap();
    let sig = ark_bls12_381::G1Affine::deserialize_compressed(sig_buf.as_slice()).unwrap();
    let pk_buf = hex::decode("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e").unwrap();
    let pk = ark_bls12_381::G2Affine::deserialize_compressed(pk_buf.as_slice()).unwrap();
    let msg_hash = hash_to_g1(DST, msg.as_slice());
    assert_eq!(ark_bls12_381::Bls12_381::pairing(msg_hash, pk), ark_bls12_381::Bls12_381::pairing(sig, ark_bls12_381::G2Affine::generator()));
}
