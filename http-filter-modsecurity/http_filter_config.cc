#include <string>
#include <memory>

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

    modsecurity::ModsecurityFilterConfigDecoder proto_config;
    translateHttpModSecurityFilter(json_config, proto_config);

    return createFilter(proto_config, context);
  }

  Http::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                     const std::string&,
                                                     FactoryContext& context) override {

    return createFilter(
        Envoy::MessageUtil::downcastAndValidate<const modsecurity::ModsecurityFilterConfigDecoder&>(proto_config), context);
  }

  /**
   *  Return the Protobuf Message that represents your config incase you have config proto
   */
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new modsecurity::ModsecurityFilterConfigDecoder()};
  }

  std::string name() override { 
    return Envoy::Http::ModSecurityFilterNames::get().ModSecurity;
  }

private:
  Http::FilterFactoryCb createFilter(const modsecurity::ModsecurityFilterConfigDecoder& proto_config, FactoryContext& context) {
    Http::HttpModSecurityFilterConfigSharedPtr config =
        std::make_shared<Http::HttpModSecurityFilterConfig>(
            Http::HttpModSecurityFilterConfig(proto_config));

    return [config, &context](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      callbacks.addStreamFilter(
        std::make_shared<Http::HttpModSecurityFilter>(config, context)
      );
    };
  }

  void translateHttpModSecurityFilter(const Json::Object& json_config,
                                        modsecurity::ModsecurityFilterConfigDecoder& proto_config) {

    // normally we want to validate the json_config againts a defined json-schema here.
    JSON_UTIL_SET_STRING(json_config, proto_config, rules_path);
    JSON_UTIL_SET_STRING(json_config, proto_config, rules_inline);
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
