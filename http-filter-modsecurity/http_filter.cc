#include <cstdlib>

#include "common/common/logger.h"
#include <string>

#include "http_filter.h"

#include "envoy/server/filter_config.h"
#include <iostream>

#include "modsecurity/rule_message.h"


using namespace std;

namespace Envoy {
namespace Http {

static void logCb(void *data, const void *ruleMessagev) {
    if (ruleMessagev == NULL) {
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
    this->modsec = new modsecurity::ModSecurity();
    this->modsec->setConnectorInformation("ModSecurity-test v0.0.1-alpha (ModSecurity test)");
    this->modsec->setServerLogCb(logCb, modsecurity::RuleMessageLogProperty
                                  | modsecurity::IncludeFullHighlightLogProperty);

    this->modsec_rules = new modsecurity::Rules();
    this->modsec_rules->loadFromUri(this->rules().c_str());
}

HttpModSecurityFilter::HttpModSecurityFilter(HttpModSecurityFilterConfigSharedPtr config)
    : config_(config) {
    modsecTransaction = new modsecurity::Transaction(this->config_->modsec, this->config_->modsec_rules, NULL);
}

HttpModSecurityFilter::~HttpModSecurityFilter() {
    delete this->modsecTransaction;
    this->modsecTransaction = NULL;
}

HttpModSecurityFilterConfig::~HttpModSecurityFilterConfig() {
    delete this->modsec;
    this->modsec = NULL;
//  TODO: check why this is segfaulting.
//  delete this->modsec_rules;
//  this->modsec_rules = NULL;
}

void HttpModSecurityFilter::onDestroy() {
    this->modsecTransaction->processLogging();
}


FilterHeadersStatus HttpModSecurityFilter::decodeHeaders(HeaderMap& headers, bool) {
  const char * uri = headers.get(LowerCaseString(":path"))->value().c_str();
  const char * method = headers.get(LowerCaseString(":method"))->value().c_str();
  this->modsecTransaction->processURI(uri, method, "1.1");
  headers.iterate(
          [](const HeaderEntry& header, void* context) -> HeaderMap::Iterate {
            static_cast<HttpModSecurityFilter*>(context)->modsecTransaction->addRequestHeader(
                    header.key().c_str(),
                    header.value().c_str()
            );
            return HeaderMap::Iterate::Continue;
            },
            this);
  this->modsecTransaction->processRequestHeaders();
  return FilterHeadersStatus::Continue;
}

FilterDataStatus HttpModSecurityFilter::decodeData(Buffer::Instance& data, bool) {
  const size_t length = data.length();
  unsigned char * buffer = new unsigned char[length]();

  // TODO: avoid duplicate copy
  data.copyOut(0, length, buffer);
  this->modsecTransaction->appendRequestBody(buffer, length);
  this->modsecTransaction->processRequestBody();
  delete buffer;
  return FilterDataStatus::Continue;
}

FilterTrailersStatus HttpModSecurityFilter::decodeTrailers(HeaderMap&) {
  return FilterTrailersStatus::Continue;
}

void HttpModSecurityFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}


FilterHeadersStatus HttpModSecurityFilter::encodeHeaders(HeaderMap& headers, bool) {
    int code = atoi(headers.get(LowerCaseString(":status"))->value().c_str());
    headers.iterate(
            [](const HeaderEntry& header, void* context) -> HeaderMap::Iterate {
                static_cast<HttpModSecurityFilter*>(context)->modsecTransaction->addResponseHeader(
                        header.key().c_str(),
                        header.value().c_str()
                );
                return HeaderMap::Iterate::Continue;
            },
            this);
    this->modsecTransaction->processResponseHeaders(code, "1.1");
    return FilterHeadersStatus::Continue;
}

FilterHeadersStatus HttpModSecurityFilter::encode100ContinueHeaders(HeaderMap& headers) {
    return FilterHeadersStatus::Continue;
}

FilterDataStatus HttpModSecurityFilter::encodeData(Buffer::Instance& data, bool) {
    const size_t length = data.length();
    unsigned char * buffer = new unsigned char[length]();

    // TODO: avoid duplicate copy
    data.copyOut(0, length, buffer);
    this->modsecTransaction->appendResponseBody(buffer, length);
    this->modsecTransaction->processResponseBody();
    delete buffer;
    return FilterDataStatus::Continue;
}

FilterTrailersStatus HttpModSecurityFilter::encodeTrailers(HeaderMap&) {
    cout << "encodeTrailers" << endl;
    return FilterTrailersStatus::Continue;
}

void HttpModSecurityFilter::setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) {
    cout << "setEncoderFilterCallbacks" << endl;
    encoder_callbacks_ = &callbacks;
}

} // namespace Http
} // namespace Envoy
