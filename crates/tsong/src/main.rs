use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match tsong::run(std::env::args().skip(1)).await {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
