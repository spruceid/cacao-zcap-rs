use async_trait::async_trait;
use cacao::siwe_cacao::SignInWithEthereum;
use cacao::{Header, Payload, SignatureScheme, Version as CacaoVersion, CACAO};
use chrono::prelude::DateTime;
use iri_string::types::UriString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use siwe::TimeStamp;
use ssi::did_resolve::DIDResolver;
use ssi::error::Error as SSIError;
use ssi::jsonld::SECURITY_V2_CONTEXT;
use ssi::jwk::JWK;
use ssi::ldp::{LinkedDataDocument, ProofPreparation, ProofSuite, VerificationWarnings};
use ssi::vc::{LinkedDataProofOptions, Proof, ProofPurpose, URI};
use ssi::zcap::{Context, Contexts, Delegation};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

pub const PROOF_TYPE_2022: &str = "CacaoZcapProof2022";
pub const CONTEXT_URL_V1: &str = "https://demo.didkit.dev/2022/cacao-zcap/context/v1.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CacaoZcapExtraProps {
    /// Type of Delegation
    pub r#type: String,

    /// Invocation target
    ///
    /// <https://w3id.org/security#invocationTarget>
    pub invocation_target: String,

    /// CACAO/Zcap expiration time
    ///
    /// <https://w3id.org/security#expires>
    /// mapped to CACAO "exp" value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// CACAO/Zcap validFrom (nbf)
    ///
    /// <https://www.w3.org/2018/credentials#validFrom>
    ///
    /// mapped to CACAO "nbf" value
    ///
    /// EIP-4361 not-before: "when the signed authentication message will become valid."
    // TODO: use https://schema.org/validFrom instead?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,

    /// CACAO payload type.
    ///
    /// CACAO header "t" value
    pub cacao_payload_type: String,

    /// CACAO statement
    ///
    /// [CACAO] payload "statement" value
    ///
    /// In [EIP-4361], statement is defined as a "human-readable ASCII assertion that the user will sign".
    ///
    /// [CACAO]: https://github.com/ChainAgnostic/CAIPs/blob/8fdb5bfd1bdf15c9daf8aacfbcc423533764dfe9/CAIPs/caip-draft_cacao.md#container-format
    /// [EIP-4361]: https://eips.ethereum.org/EIPS/eip-4361#message-field-descriptions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cacao_statement: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CacaoZcapProofExtraProps {
    /// Capability chain
    ///
    /// <https://w3id.org/security#capabilityChain>
    pub capability_chain: Vec<String>,

    /// CACAO signature type.
    ///
    /// CACAO signature "t" value
    pub cacao_signature_type: String,
}

/// Error from converting between [CacaoZcapProofConvertError] and [Proof::property_set] value
#[derive(Error, Debug)]
pub enum CacaoZcapProofConvertError {
    /// Unable to convert HashMap to Value
    #[error("Unable to convert HashMap to Value")]
    HashMapToValue(#[source] serde_json::Error),

    /// Unable to convert Value to CacaoZcapProofExtraProps
    #[error("Unable to convert Value to CacaoZcapProofExtraProps")]
    ValueToExtraProps(#[source] serde_json::Error),

    /// Unable to convert Value to HashMap
    #[error("Unable to convert Value to HashMap")]
    ValueToHashMap(#[source] serde_json::Error),

    /// Unable to convert CacaoZcapProofExtraProps to Value
    #[error("Unable to convert CacaoZcapProofExtraProps to Value")]
    ExtraPropsToValue(#[source] serde_json::Error),
}

impl CacaoZcapProofExtraProps {
    fn from_property_set_opt(
        pso: Option<HashMap<String, Value>>,
    ) -> Result<Self, CacaoZcapProofConvertError> {
        let value =
            serde_json::to_value(pso).map_err(CacaoZcapProofConvertError::HashMapToValue)?;
        let extraprops: CacaoZcapProofExtraProps =
            serde_json::from_value(value).map_err(CacaoZcapProofConvertError::ValueToExtraProps)?;
        Ok(extraprops)
    }

    fn into_property_set_opt(
        self,
    ) -> Result<Option<HashMap<String, Value>>, CacaoZcapProofConvertError> {
        let props =
            serde_json::to_value(self).map_err(CacaoZcapProofConvertError::ExtraPropsToValue)?;
        let property_set: HashMap<String, Value> =
            serde_json::from_value(props).map_err(CacaoZcapProofConvertError::ValueToHashMap)?;
        Ok(Some(property_set))
    }
}

/// Error from converting to [CACAO to a Zcap](cacao_to_zcap)
#[derive(Error, Debug)]
pub enum CacaoToZcapError {
    /// Unknown CACAO version. Expected v1.
    #[error("Unknown CACAO version")]
    UnknownCacaoVersion,

    /// Unable to parse issuedAt (iat) date
    #[error("Unable to parse issuedAt (iat) date")]
    ParseIssuedAtDate(#[source] chrono::format::ParseError),

    /// Unable to parse expiration (exp) date
    #[error("Unable to parse expiration (exp) date")]
    ParseExpDate(#[source] chrono::format::ParseError),

    /// Unknown issuer scheme. Expected PKH DID (did:pkh:).
    #[error("Unknown issuer scheme")]
    UnknownIssuerScheme,

    /// Unable to parse CACAO combined type.
    ///
    /// Expected e.g. "eip4361-eip191"
    #[error("Unable to parse CACAO type")]
    CombinedTypeParse,

    /// Unable to convert CACAO proof extra properties
    #[error("Unable to convert CACAO proof extra properties")]
    ConvertProofExtraProps(#[source] CacaoZcapProofConvertError),

    /// Delegation is missing id
    ///
    /// zcap delegation object must have an id property.
    #[error("Delegation is missing id")]
    MissingId,

    /// Missing first resource
    ///
    /// CACAO-zcap must have at least one resource URI.
    /// The first resource URI is the invocation target.
    #[error("Missing first resource")]
    MissingFirstResource,
}

fn get_header_and_signature_type(header: &Header) -> Result<(String, String), CacaoToZcapError> {
    let combined_type = header.t();
    match combined_type
        .splitn(2, '-')
        .collect::<Vec<&str>>()
        .as_slice()
    {
        [t1, t2] => Ok((t1.to_string(), t2.to_string())),
        _ => Err(CacaoToZcapError::CombinedTypeParse),
    }
}

/// Convert a CACAO to a Zcap (delegation)
pub fn cacao_to_zcap<S: SignatureScheme>(
    cacao: &CACAO<S>,
) -> Result<Delegation<(), CacaoZcapExtraProps>, CacaoToZcapError>
where
    S::Signature: AsRef<[u8]>,
{
    let header = cacao.header();
    let Payload {
        domain,
        iss: issuer,
        statement: statement_opt,
        aud,
        version,
        nonce,
        iat,
        exp: exp_opt,
        nbf: nbf_opt,
        request_id: req_id_opt,
        resources,
    } = cacao.payload();
    match version {
        CacaoVersion::V1 => {}
        #[allow(unreachable_patterns)]
        _ => return Err(CacaoToZcapError::UnknownCacaoVersion),
    }
    let signature = cacao.signature();
    let valid_from_opt = nbf_opt.as_ref().map(|nbf| nbf.to_string());
    let exp_string_opt = exp_opt.as_ref().map(|ts| ts.to_string());

    let (header_type, signature_type) = get_header_and_signature_type(header)?;
    let request_id = req_id_opt.as_ref().ok_or(CacaoToZcapError::MissingId)?;
    let id = URI::String(request_id.to_string());
    let mut iter = resources.iter();
    let (first_resource, secondary_resources) = (
        iter.next().ok_or(CacaoToZcapError::MissingFirstResource)?,
        iter,
    );

    let invocation_target = first_resource;
    let root_cap_urn = ZcapRootURN {
        target: first_resource.clone(),
    };
    let root_cap_urn_string = root_cap_urn.to_string();
    let capability_chain: Vec<String> = vec![root_cap_urn_string.clone()]
        .into_iter()
        .chain(secondary_resources.map(|r| r.to_string()))
        .collect();
    let parent_capability_id = capability_chain
        .iter()
        .next_back()
        // capability_chain has at least one value, but using unwrap_or here anyway
        .unwrap_or(&root_cap_urn_string)
        .to_string();

    let invoker_uri = URI::String(aud.as_str().to_string());
    let created_datetime = DateTime::parse_from_rfc3339(&iat.to_string())
        .map_err(CacaoToZcapError::ParseIssuedAtDate)?
        .into();

    let vm_string = if let Some(pkh) = issuer.as_str().strip_prefix("did:pkh:") {
        format!("did:pkh:{}#blockchainAccountId", pkh)
    } else {
        return Err(CacaoToZcapError::UnknownIssuerScheme);
    };
    let proof_value_string = multibase::encode(multibase::Base::Base16Lower, signature);
    let proof_extraprops = CacaoZcapProofExtraProps {
        capability_chain,
        cacao_signature_type: signature_type,
    }
    .into_property_set_opt()
    .map_err(CacaoToZcapError::ConvertProofExtraProps)?;
    let proof = Proof {
        proof_purpose: Some(ProofPurpose::CapabilityDelegation),
        proof_value: Some(proof_value_string),
        verification_method: Some(vm_string),
        domain: Some(domain.to_string()),
        nonce: Some(nonce.to_string()),
        property_set: proof_extraprops,
        created: Some(created_datetime),
        ..Proof::new(PROOF_TYPE_2022)
    };
    let delegation_extraprops = CacaoZcapExtraProps {
        r#type: String::from("CacaoZcap2022"),
        expires: exp_string_opt,
        valid_from: valid_from_opt,
        invocation_target: invocation_target.to_string(),
        cacao_payload_type: header_type,
        cacao_statement: statement_opt.clone(),
    };
    let mut delegation = Delegation {
        context: Contexts::Many(vec![
            Context::URI(URI::String(SECURITY_V2_CONTEXT.into())),
            Context::URI(URI::String(CONTEXT_URL_V1.into())),
        ]),
        invoker: Some(invoker_uri),
        ..Delegation::new(id, URI::String(parent_capability_id), delegation_extraprops)
    };
    delegation.proof = Some(proof);
    Ok(delegation)
}

/// Error from converting to [Zcap to a CACAO](zcap_to_cacao)
#[derive(Error, Debug)]
pub enum ZcapToCacaoError {
    /// Delegation object is missing a proof object
    #[error("Delegation object is missing a proof object")]
    MissingProof,

    /// Bad CACAO-ZCap Context
    ///
    /// CACAO-Zcap is expected to use specific context URIs:
    /// 1. [SECURITY_V2_CONTEXT]
    /// 2. [CONTEXT_URL_V1]
    #[error("Bad CACAO-ZCap Context")]
    BadContext,

    /// Delegation object is missing invoker property
    #[error("Delegation object is missing invoker property")]
    MissingInvoker,

    /// Proof object is missing signature (proofValue)
    #[error("Proof object is missing signature (proofValue)")]
    MissingProofValue,

    /// Unable to decode multibase proof value
    #[error("Unable to decode multbiase proof value")]
    MultibaseDecodeProofValue(#[source] multibase::Error),

    /// Unable to convert proof extra properties
    #[error("Unable to convert proof extra properties")]
    ConvertProofExtraProps(#[source] CacaoZcapProofConvertError),

    /// Unable to convert signature
    #[error("Unable to convert signature")]
    ConvertSignature,

    /// Missing verification method on proof object
    ///
    /// CACAO-Zcap proof object must have verificationMethod property.
    #[error("Missing verification method on proof object")]
    MissingProofVerificationMethod,

    /// Missing domain property of proof object
    ///
    /// CACAO-Zcap proof object must have domain property corresponding to CACAO domain value.
    #[error("Missing domain property of proof object")]
    MissingProofDomain,

    /// Missing nonce property of proof object
    ///
    /// CACAO-Zcap proof object must have nonce property corresponding to CACAO nonce value.
    #[error("Missing nonce property of proof object")]
    MissingProofNonce,

    /// Missing created property of proof object
    ///
    /// CACAO-Zcap proof object must have created property corresponding to CACAO created value.
    #[error("Missing created property of proof object")]
    MissingProofCreated,

    /// Unknown verification method scheme
    ///
    /// Expected "did:pkh:..."
    #[error("Unknown verification method scheme")]
    UnknownVerificationMethodScheme,

    /// Unknown PKH verification method URL
    ///
    /// Expected "did:pkh:...#blockchainAccountId"
    #[error("Unknown PKH verification method URL")]
    UnknownPKHVerificationMethodURL,

    /// Expected non-empty capabilityChain
    #[error("Expected non-empty capabilityChain")]
    ExpectedNonEmptyCapabilityChain,

    /// Unable to parse issuer URL
    #[error("Unable to parse issuer URL")]
    IssuerParse(#[source] iri_string::validate::Error),

    /// Unable to parse invoker URI as "aud" value
    #[error("Unable to parse invoker URI as \"aud\" value")]
    InvokerParseAud(#[source] iri_string::validate::Error),

    /// Unable to parse parse root capability URI
    ///
    /// Root capability URI (first value of
    /// [capabilityChain](CacaoZcapProofExtraProps::capability_chain) proof value)
    /// is expected to be a [ZcapRootURN].
    #[error("Unable to parse root capability URI")]
    RootURIParse(#[source] ZcapRootURNParseError),

    /// Invocation target did not match in delegation
    #[error("Invocation target did not match in delegation. Found invocationTarget value '{invocation_target}' and decoded root target URI '{decoded_root_target}'")]
    InvocationTargetInternalMismatch {
        /// [Invocation target](CacaoZcapExtraProps::invocation_target) from delegation object
        invocation_target: String,

        /// Target URL decoded from root capability URI (ZcapRootURN)
        decoded_root_target: UriString,
    },

    /// Unable to parse resource as URI
    #[error("Unable to parse resource as URI")]
    ResourceURIParse(#[source] iri_string::types::CreationError<String>),

    /// Unknown delegation type
    #[error("Unknown delegation type")]
    UnknownDelegationType,

    /// Unable to parse validFrom timestamp
    #[error("Unable to parse validFrom timestamp")]
    UnableToParseValidFromTimestamp(chrono::format::ParseError),

    /// Unable to parse expires timestamp
    #[error("Unable to parse expires timestamp")]
    UnableToParseExpiresTimestamp(chrono::format::ParseError),
}

/// Root URN for authorization capability
///
/// as proposed in <https://github.com/w3c-ccg/zcap-spec/issues/39>
pub struct ZcapRootURN {
    /// Invocation target URL for root object
    pub target: UriString,
}

/// Error from attempting to parse a [ZcapRootURN]
#[derive(Error, Debug)]
pub enum ZcapRootURNParseError {
    /// Unable to parse [root URI](ZcapRootURN)
    #[error("Unable to decode invocation target")]
    TargetDecode(#[source] core::str::Utf8Error),

    /// Unable to parse [target URL](ZcapRootURN::target)
    #[error("Unable to parse target URL")]
    TargetParse(#[source] iri_string::validate::Error),

    /// Unexpected scheme for zcap root URI. Expected URN (urn:).
    #[error("Unexpected zcap root URN (urn:zcap:root:...) but found: '{uri}'")]
    ExpectedZcapRootUrn {
        /// String found that did not match the expected pattern
        uri: String,
    },
}

impl FromStr for ZcapRootURN {
    type Err = ZcapRootURNParseError;
    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let target = if let Some(suffix) = uri.strip_prefix("urn:zcap:root:") {
            percent_encoding::percent_decode_str(suffix)
                .decode_utf8()
                .map_err(ZcapRootURNParseError::TargetDecode)?
        } else {
            return Err(ZcapRootURNParseError::ExpectedZcapRootUrn {
                uri: uri.to_string(),
            });
        };
        let target_uri =
            UriString::from_str(&target).map_err(ZcapRootURNParseError::TargetParse)?;
        Ok(Self { target: target_uri })
    }
}

impl Display for ZcapRootURN {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
        // Emulate encodeURIComponent
        const CHARS: &AsciiSet = &CONTROLS
            .add(b' ')
            .add(b'"')
            .add(b'<')
            .add(b'>')
            .add(b'`')
            .add(b':')
            .add(b'/');
        let target_encoded = utf8_percent_encode(self.target.as_str(), CHARS);
        write!(f, "urn:zcap:root:{}", target_encoded)
    }
}

/// Convert a zcap delegation to a CACAO
pub fn zcap_to_cacao<S: SignatureScheme>(
    zcap: &Delegation<(), CacaoZcapExtraProps>,
) -> Result<CACAO<S>, ZcapToCacaoError>
where
    S::Signature: TryFrom<Vec<u8>>,
{
    let Delegation {
        context: contexts,
        id,
        invoker: invoker_opt,
        property_set: zcap_extraprops,
        ..
    } = zcap;
    let CacaoZcapExtraProps {
        r#type: zcap_type,
        invocation_target,
        expires: expires_opt,
        valid_from: valid_from_opt,
        cacao_payload_type,
        cacao_statement: cacao_statement_opt,
    } = zcap_extraprops;
    let proof = zcap.proof.as_ref().ok_or(ZcapToCacaoError::MissingProof)?;
    let proof_extraprops =
        CacaoZcapProofExtraProps::from_property_set_opt(proof.property_set.clone())
            .map_err(ZcapToCacaoError::ConvertProofExtraProps)?;
    let CacaoZcapProofExtraProps {
        capability_chain,
        cacao_signature_type,
    } = proof_extraprops;
    let Proof {
        proof_purpose,
        proof_value,
        verification_method: vm_opt,
        created: created_opt,
        nonce: nonce_opt,
        domain: domain_opt,
        ..
    } = proof;
    if zcap_type != "CacaoZcap2022" {
        return Err(ZcapToCacaoError::UnknownDelegationType);
    }

    match contexts {
        Contexts::Many(contexts) => match contexts.as_slice() {
            [Context::URI(URI::String(c1)), Context::URI(URI::String(c2))]
                if c1 == SECURITY_V2_CONTEXT && c2 == CONTEXT_URL_V1 => {}
            _ => return Err(ZcapToCacaoError::BadContext),
        },
        Contexts::One(_) => return Err(ZcapToCacaoError::BadContext),
    };

    let invoker = invoker_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingInvoker)?
        .to_string();

    let sig_mb = proof_value
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofValue)?;
    let (_base, sig) =
        multibase::decode(&sig_mb).map_err(ZcapToCacaoError::MultibaseDecodeProofValue)?;

    let domain = domain_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofDomain)?;
    let nonce = nonce_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofNonce)?;
    let created = created_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofCreated)?;
    let iat = TimeStamp::from(*created);
    let nbf_opt = match valid_from_opt {
        Some(valid_from) => Some(
            TimeStamp::from_str(valid_from)
                .map_err(ZcapToCacaoError::UnableToParseValidFromTimestamp)?,
        ),
        None => None,
    };
    let exp_opt = match expires_opt {
        Some(expires) => Some(
            TimeStamp::from_str(expires)
                .map_err(ZcapToCacaoError::UnableToParseExpiresTimestamp)?,
        ),
        None => None,
    };
    // First value of capability chain is the root capability; that is decoded to get the
    // invocation target which becomes the first value of the resources array.
    // Remaining values of the capability chain are delegation capability ids, that are passed
    // through into the resources array.
    let mut iter = capability_chain.into_iter();
    let (first_cap, secondary_caps) = (
        iter.next()
            .ok_or(ZcapToCacaoError::ExpectedNonEmptyCapabilityChain)?,
        iter,
    );

    let root_cap_urn = ZcapRootURN::from_str(&first_cap).map_err(ZcapToCacaoError::RootURIParse)?;
    let root_target = root_cap_urn.target;
    let resources = vec![Ok(root_target.clone())]
        .into_iter()
        .chain(secondary_caps.map(UriString::try_from))
        .collect::<Result<Vec<UriString>, iri_string::types::CreationError<String>>>()
        .map_err(ZcapToCacaoError::ResourceURIParse)?;

    if invocation_target != root_target.as_str() {
        return Err(ZcapToCacaoError::InvocationTargetInternalMismatch {
            invocation_target: invocation_target.to_string(),
            decoded_root_target: root_target,
        });
    }
    // TODO: check parentCapability is last value (converted if first value)

    // Infer issuer (verification method controller) from verification method URL.
    let vm = vm_opt
        .as_ref()
        .ok_or(ZcapToCacaoError::MissingProofVerificationMethod)?;
    let issuer = if vm.starts_with("did:pkh:") {
        if let Some(issuer) = vm.strip_suffix("#blockchainAccountId") {
            issuer
        } else {
            return Err(ZcapToCacaoError::UnknownPKHVerificationMethodURL);
        }
    } else {
        return Err(ZcapToCacaoError::UnknownVerificationMethodScheme);
    };

    let signature = S::Signature::try_from(sig).or(Err(ZcapToCacaoError::ConvertSignature))?;
    let payload = Payload {
        domain: domain.to_string().try_into().unwrap(),
        iss: issuer.try_into().map_err(ZcapToCacaoError::IssuerParse)?,
        statement: cacao_statement_opt.clone(),
        aud: invoker
            .as_str()
            .try_into()
            .map_err(ZcapToCacaoError::InvokerParseAud)?,
        version: CacaoVersion::V1,
        nonce: nonce.to_string(),
        iat,
        exp: exp_opt,
        nbf: nbf_opt,
        request_id: Some(id.to_string()),
        resources,
    };
    let cacao = payload.sign::<S>(signature);
    Ok(cacao)
}

pub struct CacaoZcapProof2022;
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for CacaoZcapProof2022 {
    async fn sign(
        &self,
        _document: &(dyn LinkedDataDocument + Sync),
        _options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        _key: &JWK,
        _extra_proof_properties: Option<HashMap<String, Value>>,
    ) -> Result<Proof, SSIError> {
        Err(SSIError::NotImplemented)
        /*
        let has_context = document_has_context(document, CONTEXT_URL_V1)?;
        let mut proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                json!([CONTEXT_URL_V1])
            },
            ..Proof::new(PROOF_TYPE_2022)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof).await?;
        let sig = sign(&message, &key)?;
        let sig_mb = multibase::encode(multibase::Base::Base16Lower, sig);
        proof.proof_value = Some(sig_mb);
        Ok(proof)
        */
    }

    async fn prepare(
        &self,
        _document: &(dyn LinkedDataDocument + Sync),
        _options: &LinkedDataProofOptions,
        _resolver: &dyn DIDResolver,
        _public_key: &JWK,
        _extra_proof_properties: Option<HashMap<String, Value>>,
    ) -> Result<ProofPreparation, SSIError> {
        Err(SSIError::NotImplemented)
        /*
        let proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new(PROOF_TYPE_2022)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof).await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::Bytes(Base64urlUInt(message)),
        })
        */
    }

    async fn complete(
        &self,
        _preparation: ProofPreparation,
        _signature: &str,
    ) -> Result<Proof, SSIError> {
        Err(SSIError::NotImplemented)
        /*
        let mut proof = preparation.proof;
        proof.proof_value = Some(signature.to_string());
        Ok(proof)
        */
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        _resolver: &dyn DIDResolver,
    ) -> Result<VerificationWarnings, SSIError> {
        use anyhow::{anyhow, Context};

        // Note: from_property_set_opt is called again in zcap_to_cacao; this seems hard to avoid.
        let proof_extraprops =
            CacaoZcapProofExtraProps::from_property_set_opt(proof.property_set.clone())
                .context("Unable to convert extra proof properties")?;
        let mut doc = document
            .to_value()
            .context("Unable to convert zcap document to Value")?;
        doc["proof"] = proof
            .to_value()
            .context("Unable to convert zcap proof to Value")?;
        let zcap: Delegation<(), CacaoZcapExtraProps> = serde_json::from_value(doc)
            .context("Unable to convert zcap from Value to Delegation")?;
        let payload_type = zcap.property_set.cacao_payload_type.as_str();
        let signature_type = proof_extraprops.cacao_signature_type.as_str();

        let cacao = match (payload_type, signature_type) {
            ("eip4361", "eip191") => zcap_to_cacao::<SignInWithEthereum>(&zcap)
                .context("Unable to convert zcap to SIWE CACAO")?,
            (header_type, sig_type) => {
                return Err(anyhow!(
                    "Unexpected payload/signature type '{}-{}'",
                    header_type,
                    sig_type
                )
                .into());
            }
        };
        cacao.verify().await.context("Unable to verify CACAO")?;

        /* TODO: check VM
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(SSIError::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver)
            .await
            .context("Unable to resolve verification method")?;
        if vm.type_ != "EcdsaSecp256k1RecoveryMethod2020" {
            return Err(anyhow!("Unexpected verification method type").into());
        }
        let account_id: BlockchainAccountId = vm
            .blockchain_account_id
            .ok_or(anyhow!("Expected blockchainAccountId property"))?
            .parse()
            .context("Unable to parse blockchainAccountId property")?;
        // let message = to_jws_payload(document, proof).await?;
        // crate::aleo::verify(&message, &account_id.account_address, &sig)?;
        */
        Ok(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cacao::BasicSignature;
    use pretty_assertions::assert_eq;
    use siwe::Message;
    use ssi::ldp::resolve_vm;

    pub struct ExampleDIDPKH;
    use async_trait::async_trait;
    use ssi::did::{DIDMethod, Document};
    use ssi::did_resolve::{
        DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
        ERROR_NOT_FOUND, TYPE_DID_LD_JSON,
    };
    const EXAMPLE_DID: &str = "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163";
    const DOC_JSON: &str = r#"
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
      "blockchainAccountId": "https://w3id.org/security#blockchainAccountId"
    }
  ],
  "id": "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163",
  "verificationMethod": [
    {
      "id": "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163#blockchainAccountId",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163",
      "blockchainAccountId": "eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163"
    }
  ],
  "authentication": [
    "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163#blockchainAccountId"
  ],
  "assertionMethod": [
    "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163#blockchainAccountId"
  ]
}
    "#;
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDMethod for ExampleDIDPKH {
        fn name(&self) -> &'static str {
            return "pkh";
        }
        fn to_resolver(&self) -> &dyn DIDResolver {
            self
        }
    }
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDResolver for ExampleDIDPKH {
        async fn resolve(
            &self,
            did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ) {
            if did != EXAMPLE_DID {
                return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None);
            }
            let doc: Document = match serde_json::from_str(DOC_JSON) {
                Ok(doc) => doc,
                Err(err) => {
                    return (ResolutionMetadata::from_error(&err.to_string()), None, None);
                }
            };
            (
                Default::default(),
                Some(doc),
                Some(DocumentMetadata::default()),
            )
        }
    }

    #[async_std::test]
    async fn siwe_verify() {
        let message = Message::from_str(
            r#"localhost:4361 wants you to sign in with your Ethereum account:
0x6Da01670d8fc844e736095918bbE11fE8D564163

SIWE Notepad Example

URI: http://localhost:4361
Version: 1
Chain ID: 1
Nonce: kEWepMt9knR6lWJ6A
Issued At: 2021-12-07T18:28:18.807Z"#,
        )
        .unwrap();
        let payload = Payload::from(message);
        // Sanity check: verify signature
        let sig_mb = r#"f6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#;
        let (_base, sig) = multibase::decode(&sig_mb).unwrap();
        let sig = BasicSignature {
            s: sig.try_into().unwrap(),
        };
        let cacao = CACAO::<SignInWithEthereum>::new(payload, sig);
        cacao.verify().await.unwrap();
        // This SIWE is not expected to be valid as a CACAO Zcap, but is here as an example that is
        // verifiable.
    }

    #[async_std::test]
    async fn zcap_cacao_kepler_session() {
        let siwe_msg_str = include_str!("../tests/delegation0.siwe");
        let siwe_msg_sig_hex = include_str!("../tests/delegation0.siwe.sig");
        let siwe_msg = Message::from_str(siwe_msg_str).unwrap();
        let payload = Payload::from(siwe_msg);
        let (_base, sig) = multibase::decode(&format!("f{}", siwe_msg_sig_hex)).unwrap();
        let sig = BasicSignature {
            s: sig.try_into().unwrap(),
        };
        let cacao = CACAO::<SignInWithEthereum>::new(payload, sig);
        let zcap = cacao_to_zcap(&cacao).unwrap();
        let zcap_json = serde_json::to_value(&zcap).unwrap();
        let zcap_json_expected: Value =
            serde_json::from_str(include_str!("../tests/delegation0-zcap.jsonld")).unwrap();
        assert_eq!(zcap_json, zcap_json_expected);

        let _resolver = ExampleDIDPKH;
        // Verify cacao as zcap
        /* Can't call zcap.verify yet because that depends on ssi
         * having this proof type.
        use ssi::vc::Check;
        let res = zcap.verify(None, &resolver).await;
        assert_eq!(res.errors, Vec::<String>::new());
        assert!(res.checks.iter().any(|c| c == &Check::Proof));
        */

        /* Can't verify because signature is not real
        let proof = zcap.proof.as_ref().unwrap();
        let warnings = CacaoZcapProof2022
            .verify(proof, &zcap, &resolver)
            .await
            .unwrap();
        dbg!(warnings);
        */

        // Convert back
        let cacao = zcap_to_cacao::<SignInWithEthereum>(&zcap).unwrap();
        let msg: Message = cacao.payload().clone().try_into().unwrap();
        assert_eq!(msg.to_string(), siwe_msg_str);
    }
}
