use std::sync::Arc;

use blsful::inner_types::Scalar;
use credx::{
    blind::BlindCredentialRequest,
    claim::{ClaimType, ClaimValidator, ScalarClaim},
    issuer::Issuer,
    knox::bbs::BbsScheme,
    prelude::{ClaimSchema, CredentialSchema},
    secure_device::{CommitLinkSecretResponse, SecureDevice},
    CredxResult,
};
use elliptic_curve::Field;
use maplit::btreemap;
use rand_core::OsRng;

#[test]
fn test_presentation_1_credential_works() -> CredxResult<()> {
    const LABEL: &str = "Test Schema";
    const DESCRIPTION: &str = "This is a test presentation schema";
    const CRED_ID: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Scalar,
            label: "link_secret".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: Some(3),
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: None,
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: Some(u16::MAX as isize),
            }],
        },
    ];

    let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)?;

    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);

    let secure_device: Arc<dyn SecureDevice> = Arc::new(SecureDeviceImpl::new());

    let (blind_credential_request, blinder) =
        BlindCredentialRequest::<BbsScheme>::new_with_secure_device(
            &issuer_public,
            secure_device.clone(),
        )?;

    println!(
        "blind_credential_request: {}",
        serde_json::to_string(&blind_credential_request).unwrap()
    );

    let blind_claims = btreemap! { "link_secret".to_string() => ScalarClaim::from(Scalar::random(rand_core::OsRng)).into() };

    let blind_credential_bundle =
        issuer.blind_sign_credential(&blind_credential_request, &blind_claims)?;

    println!(
        "blind_credential_bundle: {}",
        serde_json::to_string(&blind_credential_bundle).unwrap()
    );

    Ok(())
}

pub struct SecureDeviceImpl {
    link_secret: Scalar,
    random_link_secret: Scalar,
}

impl SecureDeviceImpl {
    pub fn new() -> Self {
        let link_secret_hex = "5dc588150c4e55b092c606ad09f3868fa6988b6bd2651dad57396dcd85068b9e";
        let link_secret = Scalar::from_be_hex(link_secret_hex).unwrap();

        let random_link_secret_hex =
            "31838e930aa9a40a7f2adb8ab1b2e5af5d068abd1030e6ff1a7be0b5460917da";
        let random_link_secret = Scalar::from_be_hex(random_link_secret_hex).unwrap();

        Self {
            link_secret,
            random_link_secret,
        }
    }
}

impl SecureDevice for SecureDeviceImpl {
    fn commit_link_secret(
        &self,
        public_key: blsful::inner_types::G1Projective,
    ) -> CredxResult<credx::secure_device::CommitLinkSecretResponse> {
        let link_secret_commitment = public_key * self.link_secret;
        let random_link_secret_commitment = public_key * self.random_link_secret;

        Ok(CommitLinkSecretResponse {
            link_secret_commitment,
            random_link_secret_commitment,
        })
    }

    fn finalize_proof_of_knowledge(
        &self,
        challenge: blsful::inner_types::Scalar,
    ) -> CredxResult<blsful::inner_types::Scalar> {
        todo!()
    }
}

#[test]
fn rand_scalar() {
    let scalar1 = Scalar::random(&mut OsRng);
    println!("scalar1: {scalar1}");
    let scalar1_bytes = scalar1.to_be_bytes();
    let scalar1_hex = hex::encode(&scalar1_bytes);
    println!("hex scalar: {}", scalar1_hex);
    let scalar1 = Scalar::from_be_hex(&scalar1_hex).unwrap();
    println!("scalar1: {scalar1}");
}
