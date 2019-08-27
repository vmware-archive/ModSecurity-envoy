#pragma once

#include "common/config/well_known_names.h"

namespace Envoy {
namespace Http {

// TODO - merge with source/extensions/filters/http/well_known_names.h
/**
 * Well-known http filter names.
 */
class ModSecurityFilterNameValues {
public:
  const std::string ModSecurity = "envoy.filters.http.modsecurity";
};

typedef ConstSingleton<ModSecurityFilterNameValues> ModSecurityFilterNames;

/**
 * Well-known metadata filter namespaces.
 */
class ModSecurityMetadataFilterValues {
public:
  const std::string ModSecurity = "envoy.filters.http.modsecurity";
};

typedef ConstSingleton<ModSecurityMetadataFilterValues> ModSecurityMetadataFilter;

class MetadataModSecurityKeysValues {
public:
  // Disable processing requests from downstream
  const std::string DisableRequest = "disable_request";
  // Disable processing responses from upstream
  const std::string DisableResponse = "disable_response";
  // Disable ModSecurity (both for requests and responses)
  const std::string Disable = "disable";
};

typedef ConstSingleton<MetadataModSecurityKeysValues>
    MetadataModSecurityKey;

} // namespace Http
} // namespace Envoy
