use std::{env, io::Error, path::PathBuf};

fn main() -> Result<(), Error> {
	let bindings = bindgen::Builder::default()
		.header("c-src/bindgen.h")
		.clang_arg("-Ivendor/include")
		.clang_arg("-Ic-src")
		.clang_arg("-DMBEDTLS_CONFIG_FILE=\"config-mbedtls.h\"")
		.allowlist_function("mbedtls_.+")
		.parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
		.generate()
		.map_err(Error::other)?;

	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	bindings.write_to_file(out_path.join("mbedtls.rs"))?;

	let files: Vec<PathBuf> = glob::glob("vendor/library/*.c")
		.map_err(Error::other)?
		.flatten()
		.collect();
	cc::Build::new()
		.include("vendor/include")
		.include("c-src")
		.define("MBEDTLS_CONFIG_FILE", Some("\"config-mbedtls.h\""))
		.files(files)
		.compile("mbedtls");
	
	Ok(())
}
