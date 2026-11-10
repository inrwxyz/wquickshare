fn main() {
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    }
    let mut config = prost_build::Config::new();
    config.compile_protos(
        &[
            "proto/sharing_enums.proto",
            "proto/wire_format.proto",
            "proto/offline_wire_formats.proto",
            "proto/securemessage.proto",
            "proto/securegcm.proto",
            "proto/device_to_device_messages.proto",
            "proto/ukey.proto",
        ],
        &["proto/"],
    ).unwrap();
}
