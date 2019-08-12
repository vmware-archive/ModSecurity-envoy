#include <string>

#include "http_filter.h"

#include "common/config/json_utility.h"
#include "envoy/registry/registry.h"

#include "http-filter-modsecurity/http_filter.pb.h"
#include "http-filter-modsecurity/http_filter.pb.validate.h"

namespace Envoy {
namespace Server {
namespace Configuration {

class HttpModSecurityFilterConfig : public NamedHttpFilterConfigFactory {
public:
  Http::FilterFactoryCb createFilterFactory(const Json::Object& json_config, const std::string&,
                                            FactoryContext& context) override {

    modsecurity::Decoder proto_config;
    translateHttpModSecurityFilter(json_config, proto_config);

    return createFilter(proto_config, context);
  }

  Http::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                     const std::string&,
                                                     FactoryContext& context) override {

    return createFilter(
        Envoy::MessageUtil::downcastAndValidate<const modsecurity::Decoder&>(proto_config), context);
  }

  /**
   *  Return the Protobuf Message that represents your config incase you have config proto
   */
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new modsecurity::Decoder()};
  }

  std::string name() override { 
    return Envoy::Http::ModSecurityFilterNames::get().ModSecurity;
  }

private:
  Http::FilterFactoryCb createFilter(const modsecurity::Decoder& proto_config, FactoryContext&) {
    Http::HttpModSecurityFilterConfigSharedPtr config =
        std::make_shared<Http::HttpModSecurityFilterConfig>(
            Http::HttpModSecurityFilterConfig(proto_config));

    return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      auto filter = new Http::HttpModSecurityFilter(config);
      callbacks.addStreamFilter(Http::StreamFilterSharedPtr{filter});
    };
  }

  void translateHttpModSecurityFilter(const Json::Object& json_config,
                                        modsecurity::Decoder& proto_config) {

    // normally we want to validate the json_config againts a defined json-schema here.
    JSON_UTIL_SET_STRING(json_config, proto_config, rules);
  }
};

/**
 * Static registration for this sample filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<HttpModSecurityFilterConfig, NamedHttpFilterConfigFactory>
    register_;

} // namespace Configuration
} // namespace Server
} // namespace Envoy
