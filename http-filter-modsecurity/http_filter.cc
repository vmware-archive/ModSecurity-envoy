#include <cstdlib>
#include <string>
#include <vector>
#include <iostream>

#include "http_filter.h"

#include "common/common/stack_array.h"
#include "common/http/utility.h"

#include "envoy/server/filter_config.h"

#include "modsecurity/rule_message.h"

namespace Envoy {
namespace Http {

HttpModSecurityFilterConfig::HttpModSecurityFilterConfig(
    const modsecurity::Decoder& proto_config)
    : rules_(proto_config.rules()) {
    modsec_.reset(new modsecurity::ModSecurity());
    modsec_->setConnectorInformation("ModSecurity-test v0.0.1-alpha (ModSecurity test)");
    modsec_->setServerLogCb(HttpModSecurityFilter::_logCb, modsecurity::RuleMessageLogProperty |
                                    modsecurity::IncludeFullHighlightLogProperty);

    modsec_rules_.reset(new modsecurity::Rules());
    modsec_rules_->loadFromUri(rules().c_str());
}

HttpModSecurityFilter::HttpModSecurityFilter(HttpModSecurityFilterConfigSharedPtr config)
    : config_(config), intervined_(false) {
    modsecTransaction_.reset(new modsecurity::Transaction(config_->modsec_.get(), config_->modsec_rules_.get(), this));
}

HttpModSecurityFilter::~HttpModSecurityFilter() {
}

HttpModSecurityFilterConfig::~HttpModSecurityFilterConfig() {
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

FilterHeadersStatus HttpModSecurityFilter::decodeHeaders(HeaderMap& headers, bool) {
    if (intervined_) {
        return FilterHeadersStatus::Continue;
    }
    auto uri = headers.Path();
    auto method = headers.Method();

    modsecTransaction_->processURI(std::string(uri->value().getStringView()).c_str(), 
                                    std::string(method->value().getStringView()).c_str(),
                                    getProtocolString(decoder_callbacks_->streamInfo().protocol().value_or(Protocol::Http11)));
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
        decoder_callbacks_->sendLocalReply(static_cast<Http::Code>(modsecTransaction_->m_it.status), 
                                           "ModSecurity Action\n",
                                           [](Http::HeaderMap& headers) {
                                           }, absl::nullopt, "");
    }
    return intervined_;
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
                    ruleMessage->m_isDisruptive ? "Disruptive" : "Non-disruptive",
                    modsecurity::RuleMessage::log(ruleMessage));
}

} // namespace Http
} // namespace Envoy
