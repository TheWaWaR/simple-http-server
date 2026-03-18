mod config;
mod handlers;
mod server;
mod util;

use std::sync::Arc;

use config::{bind_addr_string, build_cli, build_config, print_startup};
use server::run_server;

fn main() {
    let matches = build_cli().get_matches();
    let config = match build_config(matches) {
        Ok(config) => Arc::new(config),
        Err(message) => {
            eprintln!("ERROR: {message}");
            std::process::exit(1);
        }
    };

    if !config.silent {
        print_startup(&config);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.threads)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("ERROR: failed to build tokio runtime: {err}");
            std::process::exit(1);
        }
    };

    let config_for_server = config.clone();
    runtime.block_on(async move {
        if let Err(err) = run_server(config_for_server).await {
            eprintln!(
                "ERROR: Can not bind on {}, {}",
                bind_addr_string(config.ip, config.port),
                err
            );
            std::process::exit(1);
        }
    });
}
