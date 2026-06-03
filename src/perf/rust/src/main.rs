use coquic_rust_perf::config::{parse_runtime_args, Role};
use coquic_rust_perf::metrics::{emit_summary, finalize_summary};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = match parse_runtime_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };

    if config.role == Role::Server {
        if let Err(error) = coquic_rust_perf::server::run_server(config).await {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }

    let mut summary = coquic_rust_perf::metrics::new_run_summary(&config);
    match coquic_rust_perf::client::run_client(config.clone()).await {
        Ok(done) => summary = done,
        Err(error) => {
            summary.status = "failed".to_owned();
            summary.failure_reason = Some(error.to_string());
        }
    }

    finalize_summary(&mut summary);
    if let Err(error) = emit_summary(&summary, config.json_out.as_deref()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
    if summary.status != "ok" {
        std::process::exit(1);
    }
}
