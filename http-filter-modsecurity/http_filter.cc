#include <cstdlib>
#include <string>
#include <vector>
#include <iostream>

#include "http_filter.h"

#include "common/common/stack_array.h"
#include "common/http/utility.h"
#include "common/http/headers.h"
#include "common/config/metadata.h"
#include "envoy/server/filter_config.h"

#include "modsecurity/rule_message.h"

namespace Envoy {
namespace Http {

HttpModSecurityFilterConfig::HttpModSecurityFilterConfig(const modsecurity::Decoder& proto_config)
    : rules_path_(proto_config.rules_path()),
      rules_inline_(proto_config.rules_inline()) {
    modsec_.reset(new modsecurity::ModSecurity());
    modsec_->setConnectorInformation("ModSecurity-test v0.0.1-alpha (ModSecurity test)");
    modsec_->setServerLogCb(HttpModSecurityFilter::_logCb, modsecurity::RuleMessageLogProperty |
                                                           modsecurity::IncludeFullHighlightLogProperty);

    modsec_rules_.reset(new modsecurity::Rules());
    if (!rules_path().empty()) {
        int rulesLoaded = modsec_rules_->loadFromUri(rules_path().c_str());
        ENVOY_LOG(debug, "Loading ModSecurity config from {}", rules_path());
        if (rulesLoaded == -1) {
            ENVOY_LOG(error, "Failed to load rules: {}", modsec_rules_->getParserError());
        } else {
            ENVOY_LOG(info, "Loaded {} rules", rulesLoaded);
        };
    }
    if (!rules_inline().empty()) {
        
        int rulesLoaded = modsec_rules_->load(rules_inline().c_str());
        ENVOY_LOG(debug, "Loading ModSecurity inline rules");
        if (rulesLoaded == -1) {
            ENVOY_LOG(error, "Failed to load rules: {}", modsec_rules_->getParserError());
        } else {
            ENVOY_LOG(info, "Loaded {} inline rules", rulesLoaded);
        };
    }
    
}

HttpModSecurityFilterConfig::~HttpModSecurityFilterConfig() {
}

HttpModSecurityFilter::HttpModSecurityFilter(HttpModSecurityFilterConfigSharedPtr config)
    : config_(config), intervined_(false), requestProcessed_(false), responseProcessed_(false) {
    modsecTransaction_.reset(new modsecurity::Transaction(config_->modsec_.get(), config_->modsec_rules_.get(), this));
}

HttpModSecurityFilter::~HttpModSecurityFilter() {
}


void HttpModSecurityFilter::onDestroy() {
    modsecTransaction_->processLogging();
}

const char* getProtocolString(const Protocol protocol) {
    switch (protocol) {
    case Protocol::Http10:
        return "1.0";
    case Protocol::Http11:
        return "1.1";
    case Protocol::Http2:
        return "2.0";
    }
  NOT_REACHED_GCOVR_EXCL_LINE;
}

FilterHeadersStatus HttpModSecurityFilter::decodeHeaders(HeaderMap& headers, bool end_stream) {
    ENVOY_LOG(debug, "HttpModSecurityFilter::decodeHeaders");
    if (intervined_ || requestProcessed_) {
        ENVOY_LOG(debug, "Processed");
        return getRequestHeadersStatus();
    }
    // TODO - do we want to support dynamicMetadata?
    const auto& metadata = decoder_callbacks_->route()->routeEntry()->metadata();
    const auto& disable = Envoy::Config::Metadata::metadataValue(metadata, ModSecurityMetadataFilter::get().ModSecurity, MetadataModSecurityKey::get().Disable);
    const auto& disable_request = Envoy::Config::Metadata::metadataValue(metadata, ModSecurityMetadataFilter::get().ModSecurity, MetadataModSecurityKey::get().DisableRequest);
    if (disable_request.bool_value() || disable.bool_value()) {
        ENVOY_LOG(debug, "Filter disabled");
        requestProcessed_ = true;
        return FilterHeadersStatus::Continue;
    }
    
    auto downstreamAddress = decoder_callbacks_->streamInfo().downstreamLocalAddress();
    // TODO - Upstream is (always?) still not resolved in this stage. Use our local proxy's ip. Is this what we want?
    ASSERT(decoder_callbacks_->connection() != nullptr);
    auto localAddress = decoder_callbacks_->connection()->localAddress();
    // According to documentation, downstreamAddress should never be nullptr
    ASSERT(downstreamAddress != nullptr);
    ASSERT(downstreamAddress->type() == Network::Address::Type::Ip);
    ASSERT(localAddress != nullptr);
    ASSERT(localAddress->type() == Network::Address::Type::Ip);
    modsecTransaction_->processConnection(downstreamAddress->ip()->addressAsString().c_str(), 
                                          downstreamAddress->ip()->port(),
                                          localAddress->ip()->addressAsString().c_str(), 
                                          localAddress->ip()->port());
    if (intervention()) {
        return FilterHeadersStatus::StopIteration;
    }

    auto uri = headers.Path();
    auto method = headers.Method();
    modsecTransaction_->processURI(std::string(uri->value().getStringView()).c_str(), 
                                    std::string(method->value().getStringView()).c_str(),
                                    getProtocolString(decoder_callbacks_->streamInfo().protocol().value_or(Protocol::Http11)));
    if (intervention()) {
        return FilterHeadersStatus::StopIteration;
    }
    
    headers.iterate(
            [](const HeaderEntry& header, void* context) -> HeaderMap::Iterate {
                
                std::string k = std::string(header.key().getStringView());
                std::string v = std::string(header.value().getStringView());
                static_cast<HttpModSecurityFilter*>(context)->modsecTransaction_->addRequestHeader(k.c_str(), v.c_str());
                // TODO - does this special case makes sense? it doesn't exist on apache/nginx modsecurity bridges.
                // host header is cannonized to :authority even on http older than 2 
                // see https://github.com/envoyproxy/envoy/issues/2209
                if (k == Headers::get().Host.get()) {
                    static_cast<HttpModSecurityFilter*>(context)->modsecTransaction_->addRequestHeader(Headers::get().HostLegacy.get().c_str(), v.c_str());
                }
                return HeaderMap::Iterate::Continue;
            },
            this);
    modsecTransaction_->processRequestHeaders();
    if (end_stream) {
        requestProcessed_ = true;
    }
    if (intervention()) {
        return FilterHeadersStatus::StopIteration;
    }
    return getRequestHeadersStatus();
}

FilterDataStatus HttpModSecurityFilter::decodeData(Buffer::Instance& data, bool end_stream) {
    ENVOY_LOG(debug, "HttpModSecurityFilter::decodeData");
    if (intervined_ || requestProcessed_) {
        ENVOY_LOG(debug, "Processed");
        return getRequestStatus();
    }

    uint64_t num_slices = data.getRawSlices(nullptr, 0);
    STACK_ARRAY(slices, Buffer::RawSlice, num_slices);
    data.getRawSlices(slices.begin(), num_slices);
    for (const Buffer::RawSlice& slice : slices) {
        size_t requestLen = modsecTransaction_->getRequestBodyLength();
        // If append fails or append reached the limit, test for intervention (in case SecRequestBodyLimitAction is set to Reject)
        // Note, we can't rely solely on the return value of append, when SecRequestBodyLimitAction is set to Reject it returns true and sets the intervention
        if (modsecTransaction_->appendRequestBody(static_cast<unsigned char*>(slice.mem_), slice.len_) == false ||
            (slice.len_ > 0 && requestLen == modsecTransaction_->getRequestBodyLength())) {
            ENVOY_LOG(debug, "HttpModSecurityFilter::decodeData appendRequestBody reached limit");
            if (intervention()) {
                return FilterDataStatus::StopIterationNoBuffer;
            }
            // Otherwise set to process request
            end_stream = true;
            break;
        }
    }

    if (end_stream) {
        requestProcessed_ = true;
        modsecTransaction_->processRequestBody();
    }
    if (intervention()) {
        return FilterDataStatus::StopIterationNoBuffer;
    } 
    return getRequestStatus();
}

FilterTrailersStatus HttpModSecurityFilter::decodeTrailers(HeaderMap&) {
  return FilterTrailersStatus::Continue;
}

void HttpModSecurityFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}


FilterHeadersStatus HttpModSecurityFilter::encodeHeaders(HeaderMap& headers, bool end_stream) {
    ENVOY_LOG(debug, "HttpModSecurityFilter::encodeHeaders");
    if (intervined_ || responseProcessed_) {
        ENVOY_LOG(debug, "Processed");
        return getResponseHeadersStatus();
    }
    // TODO - do we want to support dynamicMetadata?
    const auto& metadata = encoder_callbacks_->route()->routeEntry()->metadata();
    const auto& disable = Envoy::Config::Metadata::metadataValue(metadata, ModSecurityMetadataFilter::get().ModSecurity, MetadataModSecurityKey::get().Disable);
    const auto& disable_response = Envoy::Config::Metadata::metadataValue(metadata, ModSecurityMetadataFilter::get().ModSecurity, MetadataModSecurityKey::get().DisableResponse);
    if (disable.bool_value() || disable_response.bool_value()) {
        ENVOY_LOG(debug, "Filter disabled");
        responseProcessed_ = true;
        return FilterHeadersStatus::Continue;
    }

    auto status = headers.Status();
    uint64_t code = Utility::getResponseStatus(headers);
    headers.iterate(
            [](const HeaderEntry& header, void* context) -> HeaderMap::Iterate {
                static_cast<HttpModSecurityFilter*>(context)->modsecTransaction_->addResponseHeader(
                    std::string(header.key().getStringView()).c_str(),
                    std::string(header.value().getStringView()).c_str()
                );
                return HeaderMap::Iterate::Continue;
            },
            this);
    modsecTransaction_->processResponseHeaders(code, 
            getProtocolString(encoder_callbacks_->streamInfo().protocol().value_or(Protocol::Http11)));
        
    if (intervention()) {
        return FilterHeadersStatus::StopIteration;
    }
    return getResponseHeadersStatus();
}

FilterHeadersStatus HttpModSecurityFilter::encode100ContinueHeaders(HeaderMap& headers) {
    return FilterHeadersStatus::Continue;
}

FilterDataStatus HttpModSecurityFilter::encodeData(Buffer::Instance& data, bool end_stream) {
    ENVOY_LOG(debug, "HttpModSecurityFilter::encodeData");
    if (intervined_ || responseProcessed_) {
        ENVOY_LOG(debug, "Processed");
        return getResponseStatus();
    }
    
    uint64_t num_slices = data.getRawSlices(nullptr, 0);
    STACK_ARRAY(slices, Buffer::RawSlice, num_slices);
    data.getRawSlices(slices.begin(), num_slices);
    for (const Buffer::RawSlice& slice : slices) {
        size_t responseLen = modsecTransaction_->getResponseBodyLength();
        // If append fails or append reached the limit, test for intervention (in case SecResponseBodyLimitAction is set to Reject)
        // Note, we can't rely solely on the return value of append, when SecResponseBodyLimitAction is set to Reject it returns true and sets the intervention
        if (modsecTransaction_->appendResponseBody(static_cast<unsigned char*>(slice.mem_), slice.len_) == false ||
            (slice.len_ > 0 && responseLen == modsecTransaction_->getResponseBodyLength())) {
            ENVOY_LOG(debug, "HttpModSecurityFilter::encodeData appendResponseBody reached limit");
            if (intervention()) {
                return FilterDataStatus::StopIterationNoBuffer;
            }
            // Otherwise set to process response
            end_stream = true;
            break;
        }
    }

    if (end_stream) {
        responseProcessed_ = true;
        modsecTransaction_->processResponseBody();
    }
    if (intervention()) {
        return FilterDataStatus::StopIterationNoBuffer;
    }
    return getResponseStatus();
}

FilterTrailersStatus HttpModSecurityFilter::encodeTrailers(HeaderMap&) {
    return FilterTrailersStatus::Continue;
}


FilterMetadataStatus HttpModSecurityFilter::encodeMetadata(MetadataMap& metadata_map) {
    return FilterMetadataStatus::Continue;
}

void HttpModSecurityFilter::setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) {
    encoder_callbacks_ = &callbacks;
}

bool HttpModSecurityFilter::intervention() {
    if (!intervined_ && modsecTransaction_->m_it.disruptive) {
        // intervined_ must be set to true before sendLocalReply to avoid reentrancy when encoding the reply
        intervined_ = true;
        ENVOY_LOG(debug, "intervention");
        decoder_callbacks_->sendLocalReply(static_cast<Http::Code>(modsecTransaction_->m_it.status), 
                                           "ModSecurity Action\n",
                                           [](Http::HeaderMap& headers) {
                                           }, absl::nullopt, "");
    }
    return intervined_;
}


FilterHeadersStatus HttpModSecurityFilter::getRequestHeadersStatus() {
    if (intervined_) {
        ENVOY_LOG(debug, "StopIteration");
        return FilterHeadersStatus::StopIteration;
    }
    if (requestProcessed_) {
        ENVOY_LOG(debug, "Continue");
        return FilterHeadersStatus::Continue;
    }
    // If disruptive, hold until requestProcessed_, otherwise let the data flow.
    ENVOY_LOG(debug, "RuleEngine");
    return modsecTransaction_->getRuleEngineState() == modsecurity::Rules::EnabledRuleEngine ? 
                FilterHeadersStatus::StopIteration : 
                FilterHeadersStatus::Continue;
}

FilterDataStatus HttpModSecurityFilter::getRequestStatus() {
    if (intervined_) {
        ENVOY_LOG(debug, "StopIterationNoBuffer");
        return FilterDataStatus::StopIterationNoBuffer;
    }
    if (requestProcessed_) {
        ENVOY_LOG(debug, "Continue");
        return FilterDataStatus::Continue;
    }
    // If disruptive, hold until requestProcessed_, otherwise let the data flow.
    ENVOY_LOG(debug, "RuleEngine");
    return modsecTransaction_->getRuleEngineState() == modsecurity::Rules::EnabledRuleEngine ? 
                FilterDataStatus::StopIterationAndBuffer : 
                FilterDataStatus::Continue;
}

FilterHeadersStatus HttpModSecurityFilter::getResponseHeadersStatus() {
    if (intervined_ || responseProcessed_) {
        // If intervined, let encodeData return the localReply
        ENVOY_LOG(debug, "Continue");
        return FilterHeadersStatus::Continue;
    }
    // If disruptive, hold until responseProcessed_, otherwise let the data flow.
    ENVOY_LOG(debug, "RuleEngine");
    return modsecTransaction_->getRuleEngineState() == modsecurity::Rules::EnabledRuleEngine ? 
                FilterHeadersStatus::StopIteration : 
                FilterHeadersStatus::Continue;
}

FilterDataStatus HttpModSecurityFilter::getResponseStatus() {
    if (intervined_ || responseProcessed_) {
        // If intervined, let encodeData return the localReply
        ENVOY_LOG(debug, "Continue");
        return FilterDataStatus::Continue;
    }
    // If disruptive, hold until responseProcessed_, otherwise let the data flow.
    ENVOY_LOG(debug, "RuleEngine");
    return modsecTransaction_->getRuleEngineState() == modsecurity::Rules::EnabledRuleEngine ? 
                FilterDataStatus::StopIterationAndBuffer : 
                FilterDataStatus::Continue;

}

void HttpModSecurityFilter::_logCb(void *data, const void *ruleMessagev) {
    auto filter_ = reinterpret_cast<HttpModSecurityFilter*>(data);
    auto ruleMessage = reinterpret_cast<const modsecurity::RuleMessage *>(ruleMessagev);

    filter_->logCb(ruleMessage);
}


void HttpModSecurityFilter::logCb(const modsecurity::RuleMessage * ruleMessage) {
    if (ruleMessage == nullptr) {
        ENVOY_LOG(error, "ruleMessage == nullptr");
        return;
    }
    
    ENVOY_LOG(info, "Rule Id: {} phase: {}",
                    ruleMessage->m_ruleId,
                    ruleMessage->m_phase);
    ENVOY_LOG(info, "* {} action. {}",
                    // Note - since ModSecurity >= v3.0.3 disruptive actions do not invoke the callback
                    // see https://github.com/SpiderLabs/ModSecurity/commit/91daeee9f6a61b8eda07a3f77fc64bae7c6b7c36
                    ruleMessage->m_isDisruptive ? "Disruptive" : "Non-disruptive",
                    modsecurity::RuleMessage::log(ruleMessage));
}

} // namespace Http
} // namespace Envoy
