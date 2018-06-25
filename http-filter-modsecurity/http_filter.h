#pragma once



#include <string>

#include "envoy/server/filter_config.h"

#include "http-filter-modsecurity/http_filter.pb.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"

namespace Envoy {
namespace Http {

class HttpModSecurityFilterConfig {
public:
  HttpModSecurityFilterConfig(const modsecurity::Decoder& proto_config);
  ~HttpModSecurityFilterConfig();

  const std::string& rules() const { return rules_; }

  modsecurity::ModSecurity *modsec;
  modsecurity::Rules * modsec_rules;

private:
  const std::string rules_;

};

typedef std::shared_ptr<HttpModSecurityFilterConfig> HttpModSecurityFilterConfigSharedPtr;

class HttpModSecurityFilter : public StreamFilter {
public:
    HttpModSecurityFilter(HttpModSecurityFilterConfigSharedPtr);
  ~HttpModSecurityFilter();

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  FilterHeadersStatus decodeHeaders(HeaderMap&, bool) override;
  FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  FilterTrailersStatus decodeTrailers(HeaderMap&) override;
  void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks&) override;

  // Http::StreamEncoderFilter
  FilterHeadersStatus encode100ContinueHeaders(HeaderMap& headers) override;
  FilterHeadersStatus encodeHeaders(HeaderMap&, bool) override;
  FilterDataStatus encodeData(Buffer::Instance&, bool) override;
  FilterTrailersStatus encodeTrailers(HeaderMap&) override;
  void setEncoderFilterCallbacks(StreamEncoderFilterCallbacks&) override;

private:
  const HttpModSecurityFilterConfigSharedPtr config_;
  StreamDecoderFilterCallbacks* decoder_callbacks_;
  StreamEncoderFilterCallbacks* encoder_callbacks_;
  modsecurity::Transaction * modsecTransaction;
};


} // namespace Http
} // namespace Envoy
