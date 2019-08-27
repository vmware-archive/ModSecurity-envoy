#pragma once

#include <string>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"

namespace Envoy {
namespace Http {

/**
 * @return A json escaped string
 */
std::string escapeJson(const std::string& s);

/**
 * Converts a RuleMessage to json 
 * @return A json string
 */
std::string getRuleMessageAsJsonString(const modsecurity::RuleMessage* ruleMessage);

} // Http
} // Envoy
