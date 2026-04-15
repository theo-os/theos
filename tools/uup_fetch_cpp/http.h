#ifndef UUP_HTTP_H
#define UUP_HTTP_H

#include <curl/curl.h>
#include <optional>
#include <string>
#include <vector>


namespace uup {

struct HttpResponse {
  int status_code = 0;
  std::string body;
  std::string error;
};

class HttpClient {
public:
  HttpClient();
  ~HttpClient();

  HttpClient(const HttpClient &) = delete;
  HttpClient &operator=(const HttpClient &) = delete;

  HttpResponse post_soap(const std::string &url, const std::string &action,
                         const std::string &body);

private:
  CURL *curl_;
};

} // namespace uup

#endif // UUP_HTTP_H
