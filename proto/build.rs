fn main() {
    tonic_build::configure()
        .out_dir("src/")
        .format(true)
        .compile(&["proto/strapper.proto"], &["proto"])
        .unwrap()
}
