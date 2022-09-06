use clap::Parser;
use std::path::PathBuf;
use url::Url;

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    url: Url,
    #[clap(short, long)]
    host: Option<String>,
    #[clap(short, long)]
    file: PathBuf,
}

fn main() {
    let args = Args::from_args();

    let mut pac_lib = pacparser::PacParser::new().unwrap();
    let mut pac = pac_lib.load_path(args.file).unwrap();

    let host = args
        .host
        .unwrap_or_else(|| args.url.host_str().unwrap().to_string());

    println!(
        "{:#?}",
        pacparser::decode_proxy(pac.find_proxy(args.url.as_str(), &host).unwrap()).unwrap()
    );
}
