#include "webhook_fetcher.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/enum_to_int.h"
#include "common/common/hex.h"
#include "common/crypto/utility.h"
#include "common/http/headers.h"
#include "common/http/utility.h"
#include "common/crypto/utility.h"

namespace Envoy {
namespace Http {

WebhookFetcher::WebhookFetcher(Upstream::ClusterManager& cm,
                              const modsecurity::HttpUri& uri, 
                              const std::string& secret, 
                              WebhookFetcherCallback& callback)
    : cm_(cm), uri_(uri), secret_(secret.cbegin(), secret.cend()), callback_(callback) {}

WebhookFetcher::~WebhookFetcher() {}

void WebhookFetcher::invoke(const std::string& body) {
  if (!cm_.get(uri_.cluster())) {
    ENVOY_LOG(error, "Webhook can't be invoked. cluster '{}' not found", uri_.cluster());
    return;
  }
  // TODO - this conversion is unnecessary once modsecurity::HttpUri will be deprecated
  ::envoy::api::v2::core::HttpUri http_uri;
  http_uri.set_uri(uri_.uri());
  http_uri.set_cluster(uri_.cluster());
  http_uri.set_allocated_timeout(new ::google::protobuf::Duration(uri_.timeout()));

  Http::MessagePtr message = Http::Utility::prepareHeaders(http_uri);
  message->headers().insertMethod().value().setReference(Http::Headers::get().MethodValues.Post);
  message->headers().insertContentType().value().setReference(Http::Headers::get().ContentTypeValues.Json);
  message->headers().insertContentLength().value().setInteger(body.size());
  message->body() = std::make_unique<Buffer::OwnedImpl>(body);
  if (secret_.size()) {
    // Add digest to headers
    message->headers().addCopy(WebhookHeaders::get().SignatureType, WebhookConstants::get().Sha256Hmac);
    message->headers().addCopy(WebhookHeaders::get().SignatureValue, Hex::encode(Envoy::Common::Crypto::Utility::getSha256Hmac(secret_, body)));
  }

  ENVOY_LOG(debug, "Webhook [uri = {}]: start", uri_.uri());
  cm_.httpAsyncClientForCluster(uri_.cluster())
              .send(std::move(message), *this,
                    Http::AsyncClient::RequestOptions().setTimeout(std::chrono::milliseconds(
                        DurationUtil::durationToMilliseconds(uri_.timeout()))));
}

void WebhookFetcher::onSuccess(Http::MessagePtr&& response) {
  const uint64_t status_code = Http::Utility::getResponseStatus(response->headers());
  if (status_code == enumToInt(Http::Code::OK)) {
    ENVOY_LOG(debug, "Webhook [uri = {}]: success", uri_.uri());
    callback_.onSuccess(response);
  } else {
    ENVOY_LOG(debug, "Webhook [uri = {}]: bad response status code {}", uri_.uri(),
              status_code);
    callback_.onFailure(FailureReason::BadHttpStatus);
  }

}

void WebhookFetcher::onFailure(Http::AsyncClient::FailureReason reason) {
  ENVOY_LOG(debug, "Webhook [uri = {}]: network error {}", uri_.uri(), enumToInt(reason));
  callback_.onFailure(FailureReason::Network);
}

} // namespace Http
} // namespace Envoy