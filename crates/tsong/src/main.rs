use std::process::ExitCode;

fn main() -> ExitCode {
    // Built by hand: #[tokio::main] panics when the runtime can't start.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("starting the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(tsong::run(std::env::args().skip(1))) {
        Ok(report) => {
            if !report.is_empty() {
                println!("{report}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
