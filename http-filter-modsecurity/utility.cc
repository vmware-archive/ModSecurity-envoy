#include "utility.h"
#include "modsecurity/rule_message.h"

namespace Envoy {
namespace Http {

std::string escapeJson(const std::string& s) {
    std::ostringstream o;
    for (auto c = s.cbegin(); c != s.cend(); c++) {
        switch (*c) {
        case '"': o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b"; break;
        case '\f': o << "\\f"; break;
        case '\n': o << "\\n"; break;
        case '\r': o << "\\r"; break;
        case '\t': o << "\\t"; break;
        default:
            if ('\x00' <= *c && *c <= '\x1f') {
                o << "\\u"
                  << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(*c);
            } else {
                o << *c;
            }
        }
    }
    return o.str();
}

// TODO - replace with a real json (rapidjson?) implementation
std::string getRuleMessageAsJsonString(const modsecurity::RuleMessage* ruleMessage) {
    std::ostringstream ss;

    ss << std::boolalpha
       << "{" 
       << "\"accuracy\": " << ruleMessage->m_accuracy << ", "
       << "\"clientIpAddress\": \"" << escapeJson(ruleMessage->m_clientIpAddress) << "\", "
       << "\"data\": \"" << escapeJson(ruleMessage->m_data) << "\", "
       << "\"id\": \"" << escapeJson(ruleMessage->m_id) << "\", "
       << "\"isDisruptive\": " << ruleMessage->m_isDisruptive << ", "
       << "\"match\": \"" << escapeJson(ruleMessage->m_match) << "\", "
       << "\"maturity\": " << ruleMessage->m_maturity << ", "
       << "\"message\": \"" << escapeJson(ruleMessage->m_message) << "\", "
       << "\"noAuditLog\": " << ruleMessage->m_noAuditLog << ", "
       << "\"phase\": " << ruleMessage->m_phase << ", "
       << "\"reference\": \"" << escapeJson(ruleMessage->m_reference) << "\", "
       << "\"rev\": \"" << escapeJson(ruleMessage->m_rev) << "\", "
       // Rule *m_rule;
       << "\"ruleFile\": \"" << escapeJson(ruleMessage->m_ruleFile) << "\", "
       << "\"ruleId\": " << ruleMessage->m_ruleId << ", "
       << "\"ruleLine\": " << ruleMessage->m_ruleLine << ", "
       << "\"saveMessage\": " << ruleMessage->m_saveMessage << ", "
       << "\"serverIpAddress\": \"" << escapeJson(ruleMessage->m_serverIpAddress) << "\", "
       << "\"severity\": " << ruleMessage->m_severity << ", "
       << "\"uriNoQueryStringDecoded\": \"" << escapeJson(ruleMessage->m_uriNoQueryStringDecoded) << "\", "
       << "\"ver\": \"" << escapeJson(ruleMessage->m_ver) << "\", "
       << "\"tags\": [";

    auto begin = ruleMessage->m_tags.cbegin();
    auto end = ruleMessage->m_tags.cend();
    if (begin != end) {
        ss << "\"" << escapeJson(*begin++) << "\"";
    }
    while (begin != end) {
        ss << ", "
           << "\"" << escapeJson(*begin++) << "\"";
    }
    ss << "]"
       << "}";
    return ss.str();
}

} // namespace Http
} // namespace Envoy