#include "http.h"
#include "update_payload.h"
#include "xml.h"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

const char *WU_CLIENT_ENDPOINT =
  "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx";
const char *WU_CLIENT_SECURED_ENDPOINT =
  "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured";

struct UpdateFileInfo {
  std::string name;
  uint64_t size;
};

struct ChosenUpdate {
  std::string update_id;
  uint32_t revision;
  std::map<std::string, UpdateFileInfo> files;
};

struct DownloadCandidate {
  std::string name;
  uint64_t size;
  std::string url;
};

std::optional<ChosenUpdate> select_update(
  const std::string &sync_xml, const std::string &arch);

std::string random_uuid_like() {
  static int req_id = 0;
  return "F2A2A840-02BF-4C10-8EE2-9FE928509F2" + std::to_string(req_id++);
}

std::string w3c_time(std::time_t t) {
  std::stringstream ss;
  struct tm *tm = std::gmtime(&t);
  ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

std::string compose_get_cookie_request() {
  auto now =
    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::string created = w3c_time(now);
  std::string expires = w3c_time(now + 120);
  std::string uuid = random_uuid_like();
  std::string device = "dXVwLWRldmljZS10b2tlbg==";

  std::stringstream req;
  req << "<s:Envelope xmlns:a=\"http://www.w3.org/2005/08/addressing\" "
         "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
      << "<s:Header>"
      << "<a:Action "
         "s:mustUnderstand=\"1\">http://www.microsoft.com/"
         "SoftwareDistribution/"
         "Server/ClientWebService/GetCookie</a:Action>"
      << "<a:MessageID>urn:uuid:" << uuid << "</a:MessageID>"
      << "<a:To s:mustUnderstand=\"1\">" << WU_CLIENT_ENDPOINT << "</a:To>"
      << "<o:Security s:mustUnderstand=\"1\" "
         "xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/"
         "oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
      << "<u:Timestamp u:Id=\"_0\" "
         "xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/"
         "oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
      << "<u:Created>" << created << "</u:Created>"
      << "<u:Expires>" << expires << "</u:Expires>"
      << "</u:Timestamp>"
      << "<wuws:WindowsUpdateTicketsToken wsu:id=\"ClientMSA\" "
         "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/"
         "oasis-200401-wss-wssecurity-utility-1.0.xsd\" "
         "xmlns:wuws=\"http://schemas.microsoft.com/msus/2014/10/"
         "WindowsUpdateAuthorization\">"
      << "<TicketType Name=\"MSA\" Version=\"1.0\" "
         "Policy=\"MBI_SSL\"><Device>"
      << device << "</Device></TicketType>"
      << "</wuws:WindowsUpdateTicketsToken>"
      << "</o:Security>"
      << "</s:Header>"
      << "<s:Body><GetCookie "
         "xmlns=\"http://www.microsoft.com/SoftwareDistribution/Server/"
         "ClientWebService\">"
      << "<oldCookie><Expiration>" << created << "</Expiration></oldCookie>"
      << "<lastChange>" << created << "</lastChange>"
      << "<currentTime>" << created << "</currentTime>"
      << "<protocolVersion>2.0</protocolVersion>"
      << "</GetCookie></s:Body>"
      << "</s:Envelope>";
  return req.str();
}

int main(int argc, char **argv) {
  std::cout << "Starting uup_fetch C++ port...\n";

  uup::HttpClient client;
  std::string req = compose_get_cookie_request();

  std::cout << "Contacting Windows Update for cookie...\n";
  auto resp = client.post_soap(WU_CLIENT_ENDPOINT,
    "http://www.microsoft.com/SoftwareDistribution/"
    "Server/ClientWebService/GetCookie",
    req);

  if (!resp.error.empty() || resp.status_code != 200) {
    std::cerr << "Failed to fetch cookie. Code: " << resp.status_code
              << ", Error: " << resp.error << "\n";
    if (!resp.body.empty()) {
      std::cerr << "Response body:\n" << resp.body << "\n";
    }
    return 1;
  }

  std::string unescaped = uup::xml_unescape(resp.body);
  auto encrypted_data = uup::extract_tag_text(unescaped, "EncryptedData");
  if (!encrypted_data) {
    std::cerr << "GetCookie response missing EncryptedData\n";
    return 1;
  }

  std::cout << "Successfully extracted EncryptedData (length "
            << encrypted_data->size() << ")\n";

  std::string sync_req = uup::compose_fetch_update_request("amd64",
    "External",
    "Retail",
    "10.0.26100.1",
    48,
    "Production",
    "auto",
    *encrypted_data);
  std::cout << "Fetching available updates...\n";
  auto sync_resp = client.post_soap(WU_CLIENT_SECURED_ENDPOINT,
    "http://www.microsoft.com/SoftwareDistribution/Server/"
    "ClientWebService/SyncUpdates",
    sync_req);

  if (!sync_resp.error.empty() || sync_resp.status_code != 200) {
    std::cerr << "Failed to sync updates (we might need full string "
                 "serialization to fetch!). Code: "
              << sync_resp.status_code << "\n";
    if (!sync_resp.body.empty()) {
      std::cerr << "Response body:\n" << sync_resp.body << "\n";
    }
    // To test our XML block parser despite WU request failure:
    std::string mock_sync_xml =
      "<SyncUpdates><UpdateInfo UpdateID=\"12345\" "
      "RevisionNumber=\"10\"></UpdateInfo><UpdateInfo UpdateID=\"9989\" "
      "RevisionNumber=\"2\"></UpdateInfo></SyncUpdates>";
    select_update(mock_sync_xml, "amd64");
    return 1;
  }

  std::string sync_xml = uup::xml_unescape(sync_resp.body);
  select_update(sync_xml, "amd64");
}

std::optional<ChosenUpdate> select_update(
  const std::string &sync_xml, const std::string &arch) {
  auto update_infos = uup::find_all_tag_blocks(sync_xml, "UpdateInfo");
  if (update_infos.empty()) {
    std::cerr << "SyncUpdates response contained no UpdateInfo blocks"
              << std::endl;
    return std::nullopt;
  }

  std::cout << "Successfully parsed " << update_infos.size()
            << " UpdateInfo blocks!" << std::endl;

  for (const auto &info : update_infos) {
    auto update_id = uup::extract_attr(info, "UpdateID");
    auto revision = uup::extract_attr(info, "RevisionNumber");
    if (update_id) {
      std::cout << "Found Update Candidate: " << *update_id
                << " (Revision: " << revision.value_or("1") << ")" << std::endl;
    }
  }

  // In full port, we check has_wim_or_esd_files() and select.
  return std::nullopt;
}
