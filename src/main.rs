//! Substrate Node Template CLI library.
#![warn(missing_docs)]

mod chain_spec;
#[macro_use]
mod service;
mod cli;
mod command;
mod pow;

fn main() -> sc_cli::Result<()> {
	let version = sc_cli::VersionInfo {
		name: "Fawn",
		commit: env!("VERGEN_SHA_SHORT"),
		version: env!("CARGO_PKG_VERSION"),
		executable_name: "fawn",
		author: "yxf",
		description: "An experimental proof of work consensus with substrate",
		support_url: "https://github.com/yxf/fawn",
		copyright_start_year: 2020,
	};

	command::run(version)
}
