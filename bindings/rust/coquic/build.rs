use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=COQUIC_LIB_DIR");
    println!("cargo:rerun-if-env-changed=COQUIC_LIB_NAME");
    println!("cargo:rerun-if-env-changed=COQUIC_LINK_KIND");
    println!("cargo:rerun-if-env-changed=COQUIC_PKG_CONFIG_NAME");
    println!("cargo:rerun-if-env-changed=COQUIC_STATIC");
    println!("cargo:rerun-if-env-changed=COQUIC_TLS_BACKEND");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    if link_from_env() {
        return;
    }

    if link_from_pkg_config() {
        return;
    }

    let backend = env::var("COQUIC_TLS_BACKEND").unwrap_or_else(|_| "quictls".to_owned());
    panic!(
        "unable to find CoQUIC C FFI package. Build one with `zig build package -Dtls_backend={backend}` or set COQUIC_LIB_DIR/COQUIC_LIB_NAME"
    );
}

fn link_from_env() -> bool {
    let Some(lib_dir) = env::var_os("COQUIC_LIB_DIR") else {
        return false;
    };
    let lib_dir = PathBuf::from(lib_dir);
    let backend = env::var("COQUIC_TLS_BACKEND").unwrap_or_else(|_| "quictls".to_owned());
    let lib_name = env::var("COQUIC_LIB_NAME").unwrap_or_else(|_| format!("coquic-{backend}"));
    let link_kind = env::var("COQUIC_LINK_KIND").unwrap_or_else(|_| "dylib".to_owned());

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    match link_kind.as_str() {
        "static" => {
            println!("cargo:rustc-link-lib=static={lib_name}");
            let private_dir = lib_dir.join(format!("coquic-{backend}")).join("private");
            if private_dir.is_dir() {
                println!("cargo:rustc-link-search=native={}", private_dir.display());
                println!("cargo:rustc-link-lib=static=ssl");
                println!("cargo:rustc-link-lib=static=crypto");
            }
            print_unix_static_runtime_libs();
        }
        "dylib" | "shared" => {
            println!("cargo:rustc-link-lib=dylib={lib_name}");
        }
        other => panic!("unsupported COQUIC_LINK_KIND={other}; use dylib or static"),
    }

    true
}

fn link_from_pkg_config() -> bool {
    let package = pkg_config_package_name();
    let mut command = Command::new("pkg-config");
    command.arg("--libs").arg(&package);

    if env::var_os("COQUIC_STATIC").is_some() {
        command.arg("--static");
    }

    if let Some(path) = pkg_config_path_with_local_zig_out() {
        command.env("PKG_CONFIG_PATH", path);
    }

    let output = match command.output() {
        Ok(output) if output.status.success() => output,
        _ => return false,
    };

    let stdout = String::from_utf8(output.stdout).expect("pkg-config emitted non-UTF-8 output");
    let mut saw_link = false;
    for token in stdout.split_whitespace() {
        if let Some(search) = token.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={search}");
            continue;
        }
        if let Some(lib) = token.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={lib}");
            saw_link = true;
            continue;
        }
        if let Some(path) = token.strip_suffix(".a") {
            let path = Path::new(path);
            let Some(parent) = path.parent() else {
                continue;
            };
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let Some(lib) = stem.strip_prefix("lib") else {
                continue;
            };
            println!("cargo:rustc-link-search=native={}", parent.display());
            println!("cargo:rustc-link-lib=static={lib}");
            saw_link = true;
        }
    }

    saw_link
}

fn pkg_config_package_name() -> String {
    if let Ok(package) = env::var("COQUIC_PKG_CONFIG_NAME") {
        return package;
    }

    let backend = env::var("COQUIC_TLS_BACKEND").unwrap_or_else(|_| "quictls".to_owned());
    let suffix = if env::var_os("COQUIC_STATIC").is_some() {
        "-static"
    } else {
        ""
    };
    format!("coquic-{backend}{suffix}")
}

fn pkg_config_path_with_local_zig_out() -> Option<String> {
    let current = env::var_os("PKG_CONFIG_PATH").unwrap_or_default();
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR")?);
    let repo_root = manifest_dir.parent()?.parent()?.parent()?;
    let local = repo_root.join("zig-out/lib/pkgconfig");
    if !local.is_dir() {
        return current.into_string().ok().filter(|value| !value.is_empty());
    }

    let mut paths = vec![local];
    if !current.is_empty() {
        paths.extend(env::split_paths(&current));
    }
    env::join_paths(paths).ok()?.into_string().ok()
}

fn print_unix_static_runtime_libs() {
    if cfg!(target_family = "unix") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");
    }
}
