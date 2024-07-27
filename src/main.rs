use std::fs::{read, read_to_string, write};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use bb::{bootrom_keys, BbAesIv, BbAesKey, CmdHead, HashHex, Virage2, BLOCK_SIZE};
use clap::Parser;
use crunch64::gzip::compress;
use miniz_oxide::inflate::decompress_to_vec_with_limit;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use soft_aes::aes::{aes_dec_cbc, aes_enc_cbc};

const SK_SIZE: usize = 64 * 1024;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input patches file
    patches: PathBuf,

    /// Input bootrom file
    bootrom: PathBuf,

    /// Input Virage2 file
    virage2: PathBuf,

    /// Input SKSA file
    infile: PathBuf,

    /// Output SKSA file [default: <infile>.out]
    outfile: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct PatchFile {
    before_hash: Option<String>,
    after_hash: Option<String>,

    sk: Option<PatchSet>,
    #[serde(alias = "sa1")]
    sa: Option<PatchSet>,
    sa2: Option<PatchSet>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PatchSet {
    patches: Vec<Patch>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Patch {
    offset: u32,
    from: Option<u32>,
    to: u32,
}

impl Patch {
    fn apply(&self, buf: &mut [u8], verbose: bool) -> Result<()> {
        if verbose {
            println!(
                "Patching {}0x{:08X} to {:08X}",
                if let Some(f) = self.from {
                    format!("{f:08X} at ")
                } else {
                    "".into()
                },
                self.offset,
                self.to
            );
        }

        if self.offset as usize >= buf.len() - size_of::<u32>() {
            return Err(anyhow!(
                "patch out of range: {}0x{:08X} to {:08X}",
                if let Some(f) = self.from {
                    format!("{f:08X} at ")
                } else {
                    "".into()
                },
                self.offset,
                self.to
            ));
        }

        if let Some(f) = self.from {
            let word_at = u32::from_be_bytes(
                buf[self.offset as usize..self.offset as usize + size_of::<u32>()]
                    .try_into()
                    .unwrap(),
            );
            if word_at != f {
                return Err(anyhow!(
                    "bytes don't match: found {word_at:08X}, expected {f:08X}"
                ));
            }
        }

        buf[self.offset as usize..self.offset as usize + size_of::<u32>()]
            .copy_from_slice(&self.to.to_be_bytes());

        Ok(())
    }
}

fn patch_sk(
    patches: &[Patch],
    sk: &[u8],
    key: &BbAesKey,
    iv: &BbAesIv,
    verbose: bool,
) -> Result<Vec<u8>> {
    if verbose {
        println!("Decrypting SK");
    }

    let mut decrypted_sk = aes_dec_cbc(sk, key, iv, None).expect("failed to decrypt SK");

    if verbose {
        println!("Patching SK");
    }

    for patch in patches {
        patch.apply(&mut decrypted_sk, verbose)?;
    }

    if verbose {
        println!("Re-encrypting SK");
    }

    Ok(aes_enc_cbc(&decrypted_sk, key, iv, None).expect("failed to re-encrypt SK"))
}

fn patch_sa(
    patches: &[Patch],
    sa: &[u8],
    cmd: &mut CmdHead,
    common_key: &BbAesKey,
    verbose: bool,
) -> Result<Vec<u8>> {
    if verbose {
        println!("Decrypting SA key");
    }

    let key = aes_dec_cbc(&cmd.key, common_key, &cmd.common_cmd_iv, None)
        .expect("failed to decrypt SA key");

    if verbose {
        println!("SA key: {}", hex::encode_upper(&key));
        println!("SA IV: {}", hex::encode_upper(cmd.iv));
        println!("Decrypting SA");
    }

    let mut decrypted_sa = aes_dec_cbc(sa, &key, &cmd.iv, None).expect("failed to decrypt SA");

    let mut sha = Sha1::new();
    sha.update(&decrypted_sa);

    let hash = sha.finalize();

    if verbose {
        println!("SA hash before: {}", hex::encode_upper(hash));
    }

    if hash[..] != cmd.hash {
        eprintln!(
            "SA hash doesn't match CMD: found {}, expected {}",
            hex::encode_upper(hash),
            cmd.hash.to_hex()
        );
    }

    if verbose {
        println!("Patching SA");
    }

    for patch in patches {
        patch.apply(&mut decrypted_sa, verbose)?;
    }

    let mut sha = Sha1::new();
    sha.update(&decrypted_sa);

    let hash = sha.finalize();

    if verbose {
        println!("SA hash after: {}", hex::encode_upper(hash));
    }

    cmd.hash.copy_from_slice(&hash);

    if verbose {
        println!("Re-encrypting SA");
    }

    Ok(aes_enc_cbc(&decrypted_sa, &key, &cmd.iv, None).expect("failed to re-encrypt SA"))
}

fn patch_sa2(
    patches: &[Patch],
    sa2: &[u8],
    cmd: &mut CmdHead,
    sa1_cmd: &CmdHead,
    common_key: &BbAesKey,
    verbose: bool,
) -> Result<Vec<u8>> {
    if verbose {
        println!("Decrypting SA2 key");
    }

    // SA2 gets decrypted using the keys from SA1's CMD, because, since there's no way for SA1 to set up
    // the encryption hardware properly without access to the common key, it just leaves its own keys in place
    let key = aes_dec_cbc(&sa1_cmd.key, common_key, &sa1_cmd.common_cmd_iv, None)
        .expect("failed to decrypt SA2 key");

    if verbose {
        println!("SA2 key: {}", hex::encode_upper(&key));
        println!("SA2 IV: {}", hex::encode_upper(sa1_cmd.iv));
        println!("Decrypting SA2");
    }

    let decrypted_sa2 = aes_dec_cbc(sa2, &key, &sa1_cmd.iv, None).expect("failed to decrypt SA2");

    let mut sha = Sha1::new();
    sha.update(&decrypted_sa2);

    let hash = sha.finalize();

    if verbose {
        println!("SA2 hash before: {}", hex::encode_upper(hash));
    }

    if hash[..] != cmd.hash {
        eprintln!(
            "SA2 hash doesn't match CMD: found {}, expected {}",
            hex::encode_upper(hash),
            cmd.hash.to_hex()
        );
    }

    if verbose {
        println!("Decompressing SA2");
    }

    let mut decompressed_sa2 = decompress_to_vec_with_limit(&decrypted_sa2, 1024 * 1024)?;

    if verbose {
        println!("Patching SA2");
    }

    for patch in patches {
        patch.apply(&mut decompressed_sa2, verbose)?;
    }

    if verbose {
        println!("Re-compressing SA2");
    }

    let mut recompressed_sa2 = compress(&decompressed_sa2, 9, false)?.to_vec();
    recompressed_sa2.resize(recompressed_sa2.len().next_multiple_of(BLOCK_SIZE), 0);

    // should always be safe
    cmd.size = recompressed_sa2.len() as _;

    let mut sha = Sha1::new();
    sha.update(&recompressed_sa2);

    let hash = sha.finalize();

    if verbose {
        println!("SA2 hash after: {}", hex::encode_upper(hash));
    }

    cmd.hash.copy_from_slice(&hash);

    if verbose {
        println!("Re-encrypting SA2");
    }

    Ok(aes_enc_cbc(&recompressed_sa2, &key, &cmd.iv, None).expect("failed to re-encrypt SA2"))
}

fn main() -> Result<()> {
    let args = Args::parse();

    let patch_file: PatchFile = toml::from_str(&read_to_string(args.patches)?)?;

    let infile = read(&args.infile)?;

    let mut sha = Sha1::new();
    sha.update(&infile);

    let hash = sha.finalize();

    if args.verbose {
        println!("Hash before: {}", hex::encode_upper(hash));
    }

    let before_matches = match &patch_file.before_hash {
        Some(s) => hex::decode(s)? == hash[..],
        None => true,
    };

    if !before_matches {
        return Err(anyhow!(
            "Provided file hash does not match expected (got {}, expected {})",
            hex::encode_upper(hash),
            patch_file.before_hash.unwrap().to_uppercase()
        ));
    }

    let bootrom = read(&args.bootrom)?;

    let virage2 = read(&args.virage2)?;
    let v2 = Virage2::read_from_buf(&virage2)?;

    let (sk_key, sk_iv) = bootrom_keys(&bootrom)?;
    let common_key = &v2.boot_app_key;

    if args.verbose {
        println!("SK key: {}", sk_key.to_hex());
        println!("SK IV: {}", sk_iv.to_hex());
        println!("Common key: {}", common_key.to_hex());
    }

    let mut offset = 0;

    let sk = &infile[offset..offset + SK_SIZE];
    offset += SK_SIZE;

    let mut sa1_cmd = CmdHead::read_from_buf(&infile[offset..offset + CmdHead::SIZE])?;
    offset += CmdHead::SIZE;

    let sa1_crls = &infile[offset..offset.next_multiple_of(BLOCK_SIZE)];
    offset = offset.next_multiple_of(BLOCK_SIZE);

    let sa1 = &infile[offset..offset + sa1_cmd.size as usize];
    offset += sa1_cmd.size as usize;

    let mut sa2_cmd = if offset < infile.len() {
        let cmd = CmdHead::read_from_buf(&infile[offset..offset + CmdHead::SIZE])?;
        offset += CmdHead::SIZE;
        Some(cmd)
    } else {
        None
    };

    let sa2_crls = if sa2_cmd.is_some() {
        let blob = &infile[offset..offset.next_multiple_of(BLOCK_SIZE)];
        offset = offset.next_multiple_of(BLOCK_SIZE);
        Some(blob)
    } else {
        None
    };

    let sa2 = if let Some(cmd) = &sa2_cmd {
        let blob = &infile[offset..offset + cmd.size as usize];
        offset += cmd.size as usize;
        Some(blob)
    } else {
        None
    };

    // patching goes here

    let sk = if let Some(kernel) = patch_file.sk {
        &patch_sk(&kernel.patches, sk, &sk_key, &sk_iv, args.verbose)?
    } else {
        sk
    };

    let sa1 = if let Some(sysapp) = patch_file.sa {
        &patch_sa(&sysapp.patches, sa1, &mut sa1_cmd, common_key, args.verbose)?
    } else {
        sa1
    };

    let sa2 = if let Some(sysapp2) = patch_file.sa2 {
        sa2.map(|s| {
            patch_sa2(
                &sysapp2.patches,
                s,
                sa2_cmd.as_mut().unwrap(),
                &sa1_cmd,
                common_key,
                args.verbose,
            )
        })
        .transpose()?
    } else {
        sa2.map(Into::into)
    };

    let mut outfile = vec![];
    outfile.extend(sk);
    outfile.extend(&sa1_cmd.to_buf()?);
    outfile.extend(sa1_crls);
    outfile.extend(sa1);
    if let Some(cmd) = sa2_cmd {
        outfile.extend(&cmd.to_buf()?);
        outfile.extend(sa2_crls.unwrap());
        outfile.extend(sa2.unwrap());
    }

    let mut sha = Sha1::new();
    sha.update(&outfile);

    let hash = sha.finalize();

    if args.verbose {
        println!("Hash after: {}", hex::encode_upper(hash));
    }

    let after_matches = match &patch_file.after_hash {
        Some(s) => hex::decode(s)? == hash[..],
        None => true,
    };

    write(
        args.outfile.unwrap_or(args.infile.with_extension("out")),
        outfile,
    )?;

    if !after_matches {
        return Err(anyhow!(
            "Provided file hash does not match expected (got {}, expected {})",
            hex::encode_upper(hash),
            patch_file.after_hash.unwrap().to_uppercase()
        ));
    }

    println!("Done!");

    Ok(())
}
