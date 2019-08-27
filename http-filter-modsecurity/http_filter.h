#pragma once

#include <string>

#include "common/common/logger.h"
#include "envoy/server/filter_config.h"
#include "envoy/thread_local/thread_local.h"
#include "well_known_names.h"
#include "webhook_fetcher.h"

#include "http-filter-modsecurity/http_filter.pb.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"

namespace Envoy {
namespace Http {

class HttpModSecurityFilterConfig : public Logger::Loggable<Logger::Id::filter>,
                                    public WebhookFetcherCallback {
public:
  HttpModSecurityFilterConfig(const modsecurity::ModsecurityFilterConfigDecoder& proto_config,
                              Server::Configuration::FactoryContext&);
  ~HttpModSecurityFilterConfig();

  const std::string& rules_path() const { return rules_path_; }
  const std::string& rules_inline() const { return rules_inline_; }
  const modsecurity::ModsecurityWebhook& webhook() const { return webhook_; }

  WebhookFetcherSharedPtr webhook_fetcher();

  std::shared_ptr<modsecurity::ModSecurity> modsec_;
  std::shared_ptr<modsecurity::Rules> modsec_rules_;

  // Webhook Callbacks
  void onSuccess(const Http::MessagePtr& response) override;
  void onFailure(FailureReason reason) override;

private:

  struct ThreadLocalWebhook : public ThreadLocal::ThreadLocalObject {
    ThreadLocalWebhook(WebhookFetcher* webhook_fetcher) : webhook_fetcher_(webhook_fetcher) {}
    WebhookFetcherSharedPtr webhook_fetcher_;
  };

  const std::string rules_path_;
  const std::string rules_inline_;
  const modsecurity::ModsecurityWebhook webhook_;
  ThreadLocal::SlotPtr tls_;
};

typedef std::shared_ptr<HttpModSecurityFilterConfig> HttpModSecurityFilterConfigSharedPtr;

/**
 * Transaction flow:
 * 1. Disruptive?
 *   a. StopIterationAndBuffer until finished processing request
 *      a1. Should block? sendLocalReply
 *           decode should return StopIteration to avoid sending data to upstream.
 *           encode should return Continue to let local reply flow back to downstream.
 *      a2. Request is valid
 *           decode should return Continue to let request flow upstream.
 *           encode should return StopIterationAndBuffer until finished processing response
 *               a2a. Should block? goto a1.
 *               a2b. Response is valid, return Continue
 * 
 * 2. Non-disruptive - always return Continue
 *   
 */
class HttpModSecurityFilter : public StreamFilter,
                              public Logger::Loggable<Logger::Id::filter> {
public:
  /**
   * This static function will be called by modsecurity and internally invoke logCb filter's method
   */
  static void _logCb(void* data, const void* ruleMessagev);

    HttpModSecurityFilter(HttpModSecurityFilterConfigSharedPtr);
  ~HttpModSecurityFilter();

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  FilterHeadersStatus decodeHeaders(HeaderMap&, bool end_stream) override;
  FilterDataStatus decodeData(Buffer::Instance&, bool end_stream) override;
  FilterTrailersStatus decodeTrailers(HeaderMap&) override;
  void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks&) override;

  // Http::StreamEncoderFilter
  FilterHeadersStatus encode100ContinueHeaders(HeaderMap& headers) override;
  FilterHeadersStatus encodeHeaders(HeaderMap&, bool end_stream) override;
  FilterDataStatus encodeData(Buffer::Instance&, bool end_stream) override;
  FilterTrailersStatus encodeTrailers(HeaderMap&) override;
  void setEncoderFilterCallbacks(StreamEncoderFilterCallbacks&) override;
  FilterMetadataStatus encodeMetadata(MetadataMap& metadata_map) override;

private:
  const HttpModSecurityFilterConfigSharedPtr config_;
  StreamDecoderFilterCallbacks* decoder_callbacks_;
  StreamEncoderFilterCallbacks* encoder_callbacks_;
  std::shared_ptr<modsecurity::Transaction> modsec_transaction_;
  
  void logCb(const modsecurity::RuleMessage * ruleMessage);
  /**
   * @return true if intervention of current transaction is disruptive, false otherwise
   */
  bool intervention();

  FilterHeadersStatus getRequestHeadersStatus();
  FilterDataStatus getRequestStatus();

  FilterHeadersStatus getResponseHeadersStatus();
  FilterDataStatus getResponseStatus();

  // This bool is set by intervention before generating a local reply.
  // Once set, it means that for this http session is already intervined and any subsequent call to the filter's methods
  // will return ::Continue.
  // This is to allow the local reply to flow back to the downstream.
  bool intervined_;
  bool request_processed_;
  bool response_processed_;
  // TODO - convert three booleans to state?
};


} // namespace Http
} // namespace Envoy
