package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test"
)

alias(
    name = "envoy",
    actual = ":envoy-static",
)

envoy_cc_binary(
    name = "envoy-static",
    repository = "@envoy",
    deps = [
        ":libmodsecurity",
        "//http-filter-modsecurity:http_filter_lib",
        "//http-filter-modsecurity:http_filter_config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
    # Note - this really adds those as dynamic dependencies, this forces our docker image to have these libraries installed
    linkopts = ["-lyajl", "-ldl", "-lrt", "-lpcre", "-lcurl", "-lxml2", "-lGeoIP"]
)

cc_import(
    name = "libmodsecurity",
    hdrs = glob(["modsecurity/include/**"]),
    static_library = "modsecurity/libmodsecurity.a",
    visibility = ["//visibility:public"]
)
