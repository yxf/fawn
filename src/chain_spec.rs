use sp_core::{Pair, sr25519};
use sc_service;
use sp_runtime::traits::{Verify, IdentifyAccount};
use runtime::{AccountId, GenesisConfig, Signature, genesis::testnet_genesis};

// Note this is the URL for the telemetry server
//const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate `ChainSpec` type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

/// The chain specification option. This is expected to come in from the CLI and
/// is little more than one of a number of alternatives which can easily be converted
/// from a string (`--chain=...`) into a `ChainSpec`.
#[derive(Clone, Debug)]
pub enum Alternative {
	/// Whatever the current runtime is, with just Alice as an auth.
	Development,
	/// Whatever the current runtime is, with simple Alice/Bob auths.
	LocalTestnet,
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPair: Pair>(seed: &str) -> TPair::Public {
	TPair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPair: Pair>(seed: &str) -> AccountId where
	AccountPublic: From<TPair::Public>
{
	AccountPublic::from(get_from_seed::<TPair>(seed)).into_account()
}

impl Alternative {
	/// Get an actual chain config from one of the alternatives.
	pub(crate) fn load(self) -> Result<ChainSpec, String> {
		Ok(match self {
			Alternative::Development => ChainSpec::from_genesis(
				"Development", // id
				"dev", // ChainType
				|| testnet_genesis(
					get_account_id_from_seed::<sr25519::Pair>("Alice"),
					vec![
						get_account_id_from_seed::<sr25519::Pair>("Alice"),
						get_account_id_from_seed::<sr25519::Pair>("Bob"),
						get_account_id_from_seed::<sr25519::Pair>("Alice//stash"),
						get_account_id_from_seed::<sr25519::Pair>("Bob//stash"),
					],
					true,
				),      // constructor
				vec![], // boot_nodes
				None,   // telemetry_endpoints
				None,   // protocol_id
				None,   // properties
				None    // extensions
			),
			Alternative::LocalTestnet => ChainSpec::from_genesis(
				"Local Testnet",
				"local_testnet",
				|| testnet_genesis(
					get_account_id_from_seed::<sr25519::Pair>("Alice"),
					vec![
						get_account_id_from_seed::<sr25519::Pair>("Alice"),
						get_account_id_from_seed::<sr25519::Pair>("Bob"),
						get_account_id_from_seed::<sr25519::Pair>("Charlie"),
						get_account_id_from_seed::<sr25519::Pair>("Dave"),
						get_account_id_from_seed::<sr25519::Pair>("Eve"),
						get_account_id_from_seed::<sr25519::Pair>("Ferdie"),
						get_account_id_from_seed::<sr25519::Pair>("Alice//stash"),
						get_account_id_from_seed::<sr25519::Pair>("Bob//stash"),
						get_account_id_from_seed::<sr25519::Pair>("Charlie//stash"),
						get_account_id_from_seed::<sr25519::Pair>("Dave//stash"),
						get_account_id_from_seed::<sr25519::Pair>("Eve//stash"),
						get_account_id_from_seed::<sr25519::Pair>("Ferdie//stash"),
					],
					true,
				),
				vec![],
				None,
				Some("fawn"),
				None,
				None
			),
		})
	}

	pub(crate) fn from(s: &str) -> Option<Self> {
		match s {
			"dev" => Some(Alternative::Development),
			"" | "local" => Some(Alternative::LocalTestnet),
			_ => None,
		}
	}
}

pub fn load_spec(id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
	Ok(match Alternative::from(id) {
		Some(spec) => Box::new(spec.load()?),
		None => Box::new(ChainSpec::from_json_file(std::path::PathBuf::from(id))?),
	})
}
