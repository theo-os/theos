#pragma once
#include <string>
#include <vector>

namespace uup {
std::string xml_escape(const std::string &input);
std::string compose_fetch_update_request(
    const std::string& arch,
    const std::string& flight,
    const std::string& ring,
    const std::string& build,
    uint32_t sku,
    const std::string& release_type,
    const std::string& branch,
    const std::string& encrypted_data);
}