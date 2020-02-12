#pragma once

#include "crow_all.h"

namespace rtmp_authserver {

// Wrapper that only provides a default constructor to
// crow's mustache class.
class mustache_template : public crow::mustache::template_t {
public:
	mustache_template(): crow::mustache::template_t("") {}
};

} // namespace rtmp_authserver