#ifndef UUP_XML_H
#define UUP_XML_H

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace uup {

std::optional<std::string> extract_tag_text(const std::string &xml,
                                            const std::string &tag_name);
std::string xml_unescape(const std::string &input);

std::vector<std::string> find_all_tag_blocks(const std::string &xml,
                                             const std::string &tag_name);
std::optional<std::string> extract_attr(const std::string &tag_block,
                                        const std::string &attr_name);

} // namespace uup

#endif // UUP_XML_H
