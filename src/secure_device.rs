use blsful::inner_types::{G1Projective, Scalar};

use crate::CredxResult;

pub struct CommitLinkSecretResponse {
    pub link_secret_commitment: G1Projective,
    pub random_link_secret_commitment: G1Projective,
}

pub trait SecureDevice: Send + Sync {
    fn commit_link_secret(&self, public_key: G1Projective)
        -> CredxResult<CommitLinkSecretResponse>;

    fn finalize_proof_of_knowledge(&self, challenge: Scalar) -> CredxResult<Scalar>; // Returns proof
}
