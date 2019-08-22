#pragma once

#include <string>

#include "envoy/common/pure.h"
#include "envoy/upstream/cluster_manager.h"
#include "common/common/logger.h"

#include "http-filter-modsecurity/http_filter.pb.h"

namespace Envoy {
namespace Http {

/**
 * Failure reason.
 */
enum class FailureReason {
  /* A network error occurred causing remote data retrieval failure. */
  Network,
  /* The webhook endpoint didn't return 200 HTTP status code */
  BadHttpStatus
};

/**
 * Callback used by webhook fetcher.
 */
class WebhookFetcherCallback {
public:
  virtual ~WebhookFetcherCallback() = default;

  /**
   * This function will be called when webhook successfully called remote
   * @param data remote data
   */
  virtual void onSuccess(const Http::MessagePtr& response) PURE;

  /**
   * This function is called when error happens during webhook.
   * @param reason failure reason.
   */
  virtual void onFailure(FailureReason reason) PURE;
};

/**
 * Webhook fetcher.
 * Currently doesn't implement any retry mechanism
 */
class WebhookFetcher : public Logger::Loggable<Logger::Id::filter>,
                       public Http::AsyncClient::Callbacks {
public:
  WebhookFetcher(Upstream::ClusterManager& cm, 
                 const modsecurity::HttpUri& uri, 
                 const std::string& secret, 
                 WebhookFetcherCallback& callback);

  ~WebhookFetcher() override;

  // Http::AsyncClient::Callbacks
  void onSuccess(Http::MessagePtr&& response) override;
  void onFailure(Http::AsyncClient::FailureReason reason) override;

  /**
   * Calls the webhook remote URI
   */
  void invoke(const std::string& body);

  /**
   * Cancel the running webhook.
   */
  void cancel();


private:
  Upstream::ClusterManager& cm_;
  const modsecurity::HttpUri& uri_;
  const std::string secret_;
  WebhookFetcherCallback& callback_;

  Http::AsyncClient::Request* request_{};
};

using WebhookFetcherPtr = std::unique_ptr<WebhookFetcher>;

} // namespace Http
} // namespace Envoy
