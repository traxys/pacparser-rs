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
    let mut pac = pac_lib
        .load(std::fs::read_to_string(args.file).unwrap())
        .unwrap();

    println!("{:#?}", pac.find_proxy(&args.url).unwrap());
}
