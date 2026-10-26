//! Test-only key fixtures for the Go/C/Rust interoperability gate.
//! Never linked into the packaged static library or invoked on a user's node.
use rosenpass::protocol::basic_types::{SPk, SSk};
use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::ops::DerefMut;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let directory = PathBuf::from(args.next().ok_or("test fixture output required")?);
    if args.next().is_some() { return Err("expected one test fixture directory".into()); }
    // create, never reuse/replace a directory containing existing key material.
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    // The desktop gate creates a private inherited Windows ACL on the owned
    // parent before invoking this example. Unix also limits creation modes.
    builder.create(&directory)?;
    rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    for name in ["client", "server", "other"] {
        let (mut secret, mut public) = (SSk::zero(), SPk::zero());
        StaticKem.keygen(secret.secret_mut(), public.deref_mut())?;
        let materials: [(&str, &[u8]); 2] = [("secret", secret.secret()), ("public", &public[..])];
        for (suffix, bytes) in materials {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            #[cfg(windows)]
            options.share_mode(0);
            let mut file = options.open(directory.join(format!("{name}.{suffix}")))?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
    }
    println!("Generated three independent test-only Rosenpass keypairs");
    Ok(())
}
