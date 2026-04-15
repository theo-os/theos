#include "http.h"
#include <iostream>
#include <stdexcept>

namespace uup {

namespace {
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  auto *mem = static_cast<std::string *>(userp);
  mem->append(static_cast<const char *>(contents), realsize);
  return realsize;
}
} // namespace

HttpClient::HttpClient() {
  curl_ = curl_easy_init();
  if (!curl_) {
    throw std::runtime_error("Failed to initialize libcurl");
  }
}

HttpClient::~HttpClient() {
  if (curl_) {
    curl_easy_cleanup(curl_);
  }
}

HttpResponse HttpClient::post_soap(const std::string &url,
                                   const std::string &action,
                                   const std::string &body) {
  HttpResponse response;

  if (!curl_) {
    response.error = "CURL not initialized";
    return response;
  }

  curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl_, CURLOPT_POST, 1L);
  curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, body.c_str());
  curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, body.size());

  struct curl_slist *headers = nullptr;
  headers = curl_slist_append(
      headers, "Content-Type: application/soap+xml; charset=utf-8");
  headers = curl_slist_append(
      headers,
      "User-Agent: Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.50");
  if (!action.empty()) {
    std::string action_header = "SOAPAction: \"" + action + "\"";
    headers = curl_slist_append(headers, action_header.c_str());
  }
  curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response.body);
  curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER,
                   0L); // Optional for development

  CURLcode res = curl_easy_perform(curl_);
  if (res != CURLE_OK) {
    response.error = curl_easy_strerror(res);
  } else {
    long http_code = 0;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
    response.status_code = static_cast<int>(http_code);
  }

  curl_slist_free_all(headers);
  return response;
}

} // namespace uup
