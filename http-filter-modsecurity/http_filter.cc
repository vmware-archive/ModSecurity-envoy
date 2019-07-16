#include <cstdlib>

#include "common/common/logger.h"
#include "common/common/stack_array.h"

#include <string>
#include <vector>

#include "http_filter.h"

#include "envoy/server/filter_config.h"
#include <iostream>

#include "modsecurity/rule_message.h"

namespace Envoy {
namespace Http {

static void logCb(void *data, const void *ruleMessagev) {
    if (ruleMessagev == nullptr) {
        std::cout << "I've got a call but the message was null ;(";
        std::cout << std::endl;
        return;
    }

    const modsecurity::RuleMessage *ruleMessage = reinterpret_cast<const modsecurity::RuleMessage *>(ruleMessagev);
    std::cout << "Rule Id: " << std::to_string(ruleMessage->m_ruleId);
    std::cout << " phase: " << std::to_string(ruleMessage->m_phase);
    std::cout << std::endl;
    if (ruleMessage->m_isDisruptive) {
        std::cout << " * Disruptive action: ";
        std::cout << modsecurity::RuleMessage::log(ruleMessage);
        std::cout << std::endl;
        std::cout << " ** %d is meant to be informed by the webserver.";
        std::cout << std::endl;
    } else {
        std::cout << " * Match, but no disruptive action: ";
        std::cout << modsecurity::RuleMessage::log(ruleMessage);
        std::cout << std::endl;
    }
}

HttpModSecurityFilterConfig::HttpModSecurityFilterConfig(
    const modsecurity::Decoder& proto_config)
    : rules_(proto_config.rules()) {
    modsec_.reset(new modsecurity::ModSecurity());
    modsec_->setConnectorInformation("ModSecurity-test v0.0.1-alpha (ModSecurity test)");
    modsec_->setServerLogCb(logCb, modsecurity::RuleMessageLogProperty
                                  | modsecurity::IncludeFullHighlightLogProperty);

    modsec_rules_.reset(new modsecurity::Rules());
    modsec_rules_->loadFromUri(rules().c_str());
}

HttpModSecurityFilter::HttpModSecurityFilter(HttpModSecurityFilterConfigSharedPtr config)
    : config_(config), intervined_(false) {
    modsecTransaction_.reset(new modsecurity::Transaction(config_->modsec_.get(), config_->modsec_rules_.get(), nullptr));
}

HttpModSecurityFilter::~HttpModSecurityFilter() {
}

HttpModSecurityFilterConfig::~HttpModSecurityFilterConfig() {
}

void HttpModSecurityFilter::onDestroy() {
    modsecTransaction_->processLogging();
}

FilterHeadersStatus HttpModSecurityFilter::decodeHeaders(HeaderMap& headers, bool) {
    if (intervined_) {
        return FilterHeadersStatus::Continue;
    }
    auto uri = headers.get(LowerCaseString(":path"));
    auto method = headers.get(LowerCaseString(":method"));
    // TODO - dynamically determine by connection if HTTP/1.1. or HTTP/2?
    modsecTransaction_->processURI(std::string(uri->value().getStringView()).c_str(), 
                                    std::string(method->value().getStringView()).c_str(), 
                                    "1.1");
    headers.iterate(
            [](const HeaderEntry& header, void* context) -> HeaderMap::Iterate {
                static_cast<HttpModSecurityFilter*>(context)->modsecTransaction_->addRequestHeader(
                        std::string(header.key().getStringView()).c_str(),
                        std::string(header.value().getStringView()).c_str()
                );
                return HeaderMap::Iterate::Continue;
                },
                this);
    modsecTransaction_->processRequestHeaders();
    return intervention() ? FilterHeadersStatus::StopAllIterationAndBuffer : FilterHeadersStatus::Continue;
}

FilterDataStatus HttpModSecurityFilter::decodeData(Buffer::Instance& data, bool) {
    if (intervined_) {
        return FilterDataStatus::Continue;
    }
    uint64_t num_slices = data.getRawSlices(nullptr, 0);
    STACK_ARRAY(slices, Buffer::RawSlice, num_slices);
    data.getRawSlices(slices.begin(), num_slices);
    
    for (const Buffer::RawSlice& slice : slices) {
        modsecTransaction_->appendRequestBody(static_cast<unsigned char*>(slice.mem_), slice.len_);
    }
    modsecTransaction_->processRequestBody();
    return intervention() ? FilterDataStatus::StopIterationAndBuffer : FilterDataStatus::Continue;
}

FilterTrailersStatus HttpModSecurityFilter::decodeTrailers(HeaderMap&) {
  return FilterTrailersStatus::Continue;
}

void HttpModSecurityFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}


FilterHeadersStatus HttpModSecurityFilter::encodeHeaders(HeaderMap& headers, bool) {
    if (intervined_) {
        return FilterHeadersStatus::Continue;
    }
    auto status = headers.get(LowerCaseString(":status"));
    int code = atoi(std::string(status->value().getStringView()).c_str());
    headers.iterate(
            [](const HeaderEntry& header, void* context) -> HeaderMap::Iterate {
                static_cast<HttpModSecurityFilter*>(context)->modsecTransaction_->addResponseHeader(
                    std::string(header.key().getStringView()).c_str(),
                    std::string(header.value().getStringView()).c_str()
                );
                return HeaderMap::Iterate::Continue;
            },
            this);
    modsecTransaction_->processResponseHeaders(code, "1.1");
    return intervention() ? FilterHeadersStatus::StopAllIterationAndBuffer : FilterHeadersStatus::Continue;
}

FilterHeadersStatus HttpModSecurityFilter::encode100ContinueHeaders(HeaderMap& headers) {
    return FilterHeadersStatus::Continue;
}

FilterDataStatus HttpModSecurityFilter::encodeData(Buffer::Instance& data, bool) {
    if (intervined_) {
        return FilterDataStatus::Continue;
    }
    
    uint64_t num_slices = data.getRawSlices(nullptr, 0);
    STACK_ARRAY(slices, Buffer::RawSlice, num_slices);
    data.getRawSlices(slices.begin(), num_slices);
    
    for (const Buffer::RawSlice& slice : slices) {
        modsecTransaction_->appendResponseBody(static_cast<unsigned char*>(slice.mem_), slice.len_);
    }
    modsecTransaction_->processResponseBody();
    return intervention() ? FilterDataStatus::StopIterationAndBuffer : FilterDataStatus::Continue;
}

FilterTrailersStatus HttpModSecurityFilter::encodeTrailers(HeaderMap&) {
    std::cout << "encodeTrailers" << std::endl;
    return FilterTrailersStatus::Continue;
}


FilterMetadataStatus HttpModSecurityFilter::encodeMetadata(MetadataMap& metadata_map) {
    std::cout << "encodeMetadata" << std::endl;
    return FilterMetadataStatus::Continue;
}

void HttpModSecurityFilter::setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) {
    std::cout << "setEncoderFilterCallbacks" << std::endl;
    encoder_callbacks_ = &callbacks;
}

bool HttpModSecurityFilter::intervention() {
    if (!intervined_ && modsecTransaction_->m_it.disruptive) {
        // intervined_ must be set to true before sendLocalReply to avoid reentrancy when encoding the reply
        intervined_ = true;
        decoder_callbacks_->sendLocalReply(Code::Forbidden, "ModSecurity Action\n",
                                           [](Http::HeaderMap& headers) {
                                           }, absl::nullopt, "");
    }
    return intervined_;
}

} // namespace Http
} // namespace Envoy
