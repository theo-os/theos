#include "xml.h"

namespace uup {

std::optional<std::string> extract_tag_text(const std::string &xml,
                                            const std::string &tag_name) {
  std::string start_tag = "<" + tag_name + ">";
  std::string end_tag = "</" + tag_name + ">";

  auto start_pos = xml.find(start_tag);
  if (start_pos == std::string::npos) {
    start_tag = "<" + tag_name + " ";
    start_pos = xml.find(start_tag);
    if (start_pos == std::string::npos) {
      return std::nullopt;
    }
    start_pos = xml.find('>', start_pos);
    if (start_pos == std::string::npos) {
      return std::nullopt;
    }
  } else {
    start_pos += start_tag.length() - 1;
  }

  auto end_pos = xml.find(end_tag, start_pos);
  if (end_pos == std::string::npos) {
    return std::nullopt;
  }

  return xml.substr(start_pos + 1, end_pos - start_pos - 1);
}

std::string xml_unescape(const std::string &input) {
  std::string output;
  output.reserve(input.length());
  for (size_t i = 0; i < input.length(); ++i) {
    if (input[i] == '&') {
      if (input.compare(i, 4, "&lt;") == 0) {
        output += '<';
        i += 3;
      } else if (input.compare(i, 4, "&gt;") == 0) {
        output += '>';
        i += 3;
      } else if (input.compare(i, 5, "&amp;") == 0) {
        output += '&';
        i += 4;
      } else if (input.compare(i, 6, "&quot;") == 0) {
        output += '"';
        i += 5;
      } else if (input.compare(i, 6, "&apos;") == 0) {
        output += '\'';
        i += 5;
      } else {
        output += '&';
      }
    } else {
      output += input[i];
    }
  }
  return output;
}

std::vector<std::string> find_all_tag_blocks(const std::string &xml,
                                             const std::string &tag_name) {
  std::vector<std::string> results;
  std::string start_tag_exact = "<" + tag_name + ">";
  std::string start_tag_space = "<" + tag_name + " ";
  std::string end_tag = "</" + tag_name + ">";

  size_t pos = 0;
  while (pos < xml.length()) {
    size_t start_pos = xml.find(start_tag_exact, pos);
    size_t start_pos_space = xml.find(start_tag_space, pos);

    if (start_pos == std::string::npos &&
        start_pos_space == std::string::npos) {
      break;
    }

    size_t actual_start;
    if (start_pos == std::string::npos)
      actual_start = start_pos_space;
    else if (start_pos_space == std::string::npos)
      actual_start = start_pos;
    else
      actual_start = std::min(start_pos, start_pos_space);

    size_t tag_end = xml.find('>', actual_start);
    if (tag_end == std::string::npos)
      break;

    size_t content_start = actual_start; // Include the starting tag
    size_t end_pos = xml.find(end_tag, tag_end);

    if (end_pos == std::string::npos)
      break;

    size_t block_end = end_pos + end_tag.length();
    results.push_back(xml.substr(content_start, block_end - content_start));

    pos = block_end;
  }

  return results;
}

std::optional<std::string> extract_attr(const std::string &tag_block,
                                        const std::string &attr_name) {
  std::string attr_prefix = attr_name + "=\"";
  size_t start_pos = tag_block.find(attr_prefix);
  if (start_pos == std::string::npos)
    return std::nullopt;

  start_pos += attr_prefix.length();
  size_t end_pos = tag_block.find('"', start_pos);
  if (end_pos == std::string::npos)
    return std::nullopt;

  return tag_block.substr(start_pos, end_pos - start_pos);
}

} // namespace uup
