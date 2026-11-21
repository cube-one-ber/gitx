#[tokio::main]
async fn main() {
    match gitx_sim::run_benchmarks().await {
        Ok(report) => {
            println!("{}", gitx_sim::format_markdown_report(&report));
        }
        Err(err) => {
            eprintln!("gitx-bench error: {err}");
            std::process::exit(1);
        }
    }
}
