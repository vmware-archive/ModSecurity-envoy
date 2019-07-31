package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        "//:libmodsecurity",
        "//http-filter-modsecurity:http_filter_lib",
        "//http-filter-modsecurity:http_filter_config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
    linkopts = ["-lyajl", "-ldl", "-lrt", "-lpcre", "-lcurl", "-lxml2", "-lGeoIP"]
)

cc_import(
    name = "libmodsecurity",
    hdrs = glob(["modsecurity/include/**"]),
    static_library = "modsecurity/libmodsecurity.a",
    visibility = ["//visibility:public"]
)
