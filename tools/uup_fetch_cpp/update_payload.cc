#include "update_payload.h"
#include <sstream>
#include <chrono>
#include <iomanip>
#include <random>
#include <vector>
#include <algorithm>
#include "xml.h"

namespace uup {

std::string xml_escape(const std::string &input) {
    std::string result;
    result.reserve(input.size() * 1.2);
    for (char c : input) {
        switch (c) {
            case '&':  result += "&amp;";       break;
            case '\"': result += "&quot;";      break;
            case '\'': result += "&apos;";      break;
            case '<':  result += "&lt;";        break;
            case '>':  result += "&gt;";        break;
            default:   result += c;             break;
        }
    }
    return result;
}

static std::string random_uuid_like() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);

    const char* hex = "0123456789abcdef";
    std::string uuid = "00000000-0000-4000-8000-000000000000";

    for (int i = 0; i < 36; i++) {
        if (uuid[i] == '0') {
            uuid[i] = hex[dis(gen)];
        } else if (uuid[i] == '8') {
            uuid[i] = hex[dis2(gen)];
        }
    }
    return uuid;
}

static uint64_t unix_time() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static std::string w3c_time(uint64_t t) {
    std::time_t temp = t;
    struct tm *tm_info = std::gmtime(&temp);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    return std::string(buffer);
}

static std::string uup_device() {
    // simplified since we only need base64 encoded pseudo token.
    return "dXVwLWRldmljZS10b2tlbg==";
}

static bool args_sku_is_server(uint32_t sku) {
    const uint32_t server_skus[] = {
        7, 8, 12, 13, 79, 80, 120, 145, 146, 147, 148, 159, 160, 406, 407, 408
    };
    for (auto s : server_skus) {
        if (s == sku) return true;
    }
    return false;
}

static std::string branch_from_build(const std::string& build) {
    auto first_dot = build.find('.');
    if (first_dot == std::string::npos) return "Retail";
    auto second_dot = build.find('.', first_dot + 1);
    if (second_dot == std::string::npos) return "Retail";
    
    std::string build_str = build.substr(first_dot + 1, second_dot - first_dot - 1);
    int build_num = std::stoi(build_str);

    if (build_num >= 21390) return "Dev";
    if (build_num >= 21286) return "WIF";
    if (build_num >= 19536) return "WIF";
    if (build_num >= 18970) return "WIF";
    return "Retail";
}

static std::vector<std::string> split_arches(const std::string& arch) {
    std::string lower_arch = arch;
    for(auto& c : lower_arch) c = std::tolower(c);
    
    if (lower_arch == "all") {
        return {"amd64", "x86", "arm64", "arm"};
    }
    return {arch};
}

static const uint32_t INSTALLED_NON_LEAF_IDS[] = {
    1, 10, 105939029, 105995585, 106017178, 107825194, 10809856, 11,
    117765322, 129905029, 130040030, 130040031, 130040032, 130040033,
    133399034, 138372035, 138372036, 139536037, 139536038, 139536039,
    139536040, 142045136, 158941041, 158941042, 158941043, 158941044,
    159776047, 160733048, 160733049, 160733050, 160733051, 160733055,
    160733056, 161870057, 161870058, 161870059, 17, 19, 2, 23110993,
    23110994, 23110995, 23110996, 23110999, 23111000, 23111001, 23111002,
    23111003, 23111004, 2359974, 2359977, 24513870, 28880263, 296374060,
    3, 30077688, 30486944, 5143990, 5169043, 5169044, 5169047, 59830006,
    59830007, 59830008, 60484010, 62450018, 62450019, 62450020, 69801474,
    8788830
};

static std::string compose_device_attributes(
    const std::string& flight_val,
    const std::string& ring_val,
    const std::string& build,
    const std::string& arch,
    uint32_t sku,
    const std::string& release_type,
    const std::string& branch_val
) {
    std::string branch = branch_val;
    if (branch == "auto") {
        branch = branch_from_build(build);
    }
    
    int block_upgrades = 0;
    int flight_enabled = 1;
    int is_retail = 0;
    
    if (sku == 125 || sku == 126) block_upgrades = 1;
    
    std::string device_family = "Windows.Desktop";
    std::string installation_type = "Client";
    std::string product_type = "WinNT";
    
    if (sku == 119) device_family = "Windows.Team";
    if (args_sku_is_server(sku)) {
        device_family = "Windows.Server";
        installation_type = "Server";
        product_type = "ServerNT";
        block_upgrades = 1;
    }
    if (sku == 180 || sku == 184 || sku == 189) {
        device_family = "Windows.Core";
        installation_type = "FactoryOS";
    }
    
    std::string ring = ring_val;
    for(auto& c : ring) c = std::toupper(c);
    
    std::string flt_branch = "";
    std::string flt_ring = "External";
    
    if (ring == "RETAIL") { flt_ring = "Retail"; flight_enabled = 0; is_retail = 1; }
    if (ring == "WIF") flt_branch = "Dev";
    if (ring == "WIS") flt_branch = "Beta";
    if (ring == "RP") flt_branch = "ReleasePreview";
    if (ring == "DEV") { flt_branch = "Dev"; ring = "WIF"; }
    if (ring == "BETA") { flt_branch = "Beta"; ring = "WIS"; }
    if (ring == "RELEASEPREVIEW") { flt_branch = "ReleasePreview"; ring = "RP"; }
    if (ring == "MSIT") { flt_branch = "MSIT"; flt_ring = "Internal"; }
    if (ring == "CANARY") { flt_branch = "CanaryChannel"; ring = "WIF"; }
    
    uint64_t now = unix_time();
    uint64_t expires = now + 82800;
    uint64_t timestamp = now > 3600 ? now - 3600 : 0;
    
    std::vector<std::string> attrs = {
        "App=WU_OS",
        "AppVer=" + build,
        "AttrDataVer=331",
        "AllowInPlaceUpgrade=1",
        "AllowOptionalContent=1",
        "AllowUpgradesWithUnsupportedTPMOrCPU=1",
        "BlockFeatureUpdates=" + std::to_string(block_upgrades),
        "BranchReadinessLevel=CB",
        "CIOptin=1",
        "CurrentBranch=" + branch,
        "DataExpDateEpoch_GE25H2=" + std::to_string(expires),
        "DataExpDateEpoch_GE24H2=" + std::to_string(expires),
        "DataExpDateEpoch_GE24H2Setup=" + std::to_string(expires),
        "DataExpDateEpoch_CU23H2=" + std::to_string(expires),
        "DataExpDateEpoch_CU23H2Setup=" + std::to_string(expires),
        "DataExpDateEpoch_NI22H2=" + std::to_string(expires),
        "DataExpDateEpoch_NI22H2Setup=" + std::to_string(expires),
        "DataExpDateEpoch_CO21H2=" + std::to_string(expires),
        "DataExpDateEpoch_CO21H2Setup=" + std::to_string(expires),
        "DataExpDateEpoch_23H2=" + std::to_string(expires),
        "DataExpDateEpoch_22H2=" + std::to_string(expires),
        "DataExpDateEpoch_21H2=" + std::to_string(expires),
        "DataExpDateEpoch_21H1=" + std::to_string(expires),
        "DataExpDateEpoch_20H1=" + std::to_string(expires),
        "DataExpDateEpoch_19H1=" + std::to_string(expires),
        "DataVer_RS5=2000000000",
        "DefaultUserRegion=191",
        "DeviceFamily=" + device_family,
        "DeviceInfoGatherSuccessful=1",
        "EKB19H2InstallCount=1",
        "EKB19H2InstallTimeEpoch=1255000000",
        "FlightingBranchName=" + flt_branch,
        "FlightRing=" + flt_ring,
        "Free=gt64",
        "GStatus_GE25H2=2",
        "GStatus_GE24H2=2",
        "GStatus_GE24H2Setup=2",
        "GStatus_CU23H2=2",
        "GStatus_CU23H2Setup=2",
        "GStatus_NI23H2=2",
        "GStatus_NI22H2=2",
        "GStatus_NI22H2Setup=2",
        "GStatus_CO21H2=2",
        "GStatus_CO21H2Setup=2",
        "GStatus_22H2=2",
        "GStatus_21H2=2",
        "GStatus_21H1=2",
        "GStatus_20H1=2",
        "GStatus_20H1Setup=2",
        "GStatus_19H1=2",
        "GStatus_19H1Setup=2",
        "GStatus_RS5=2",
        "GenTelRunTimestamp_19H1=" + std::to_string(timestamp),
        "InstallDate=1438196400",
        "InstallLanguage=en-US",
        "InstallationType=" + installation_type,
        "IsDeviceRetailDemo=0",
        "IsFlightingEnabled=" + std::to_string(flight_enabled),
        "IsRetailOS=" + std::to_string(is_retail),
        "LCUVer=0.0.0.0",
        "MediaBranch=",
        "MediaVersion=" + build,
        "CloudPBR=1",
        "DUScan=1",
        "OEMModel=21F6CTO1WW",
        "OEMModelBaseBoard=21F6CTO1WW",
        "OEMName_Uncleaned=LENOVO",
        "OemPartnerRing=UPSFlighting",
        "OSArchitecture=" + arch,
        "OSSkuId=" + std::to_string(sku),
        "OSUILocale=en-US",
        "OSVersion=" + build,
        "ProcessorIdentifier=Intel64 Family 6 Model 186 Stepping 3",
        "ProcessorManufacturer=GenuineIntel",
        "ProcessorModel=13th Gen Intel(R) Core(TM) i7-1355U",
        "ProductType=" + product_type,
        "ReleaseType=" + release_type,
        "SdbVer_20H1=2000000000",
        "SdbVer_19H1=2000000000",
        "SecureBootCapable=1",
        "TelemetryLevel=3",
        "TimestampEpochString_GE24H2=" + std::to_string(timestamp),
        "TimestampEpochString_GE24H2Setup=" + std::to_string(timestamp),
        "TimestampEpochString_CU23H2=" + std::to_string(timestamp),
        "TimestampEpochString_CU23H2Setup=" + std::to_string(timestamp),
        "TimestampEpochString_NI23H2=" + std::to_string(timestamp),
        "TimestampEpochString_NI22H2=" + std::to_string(timestamp),
        "TimestampEpochString_NI22H2Setup=" + std::to_string(timestamp),
        "TimestampEpochString_CO21H2=" + std::to_string(timestamp),
        "TimestampEpochString_CO21H2Setup=" + std::to_string(timestamp),
        "TimestampEpochString_22H2=" + std::to_string(timestamp),
        "TimestampEpochString_21H2=" + std::to_string(timestamp),
        "TimestampEpochString_21H1=" + std::to_string(timestamp),
        "TimestampEpochString_20H1=" + std::to_string(timestamp),
        "TimestampEpochString_19H1=" + std::to_string(timestamp),
        "TPMVersion=2",
        "UpdateManagementGroup=2",
        "UpdateOfferedDays=0",
        "UpgEx_GE25H2=Green",
        "UpgEx_GE24H2Setup=Green",
        "UpgEx_GE24H2=Green",
        "UpgEx_CU23H2=Green",
        "UpgEx_NI23H2=Green",
        "UpgEx_NI22H2=Green",
        "UpgEx_CO21H2=Green",
        "UpgEx_23H2=Green",
        "UpgEx_22H2=Green",
        "UpgEx_21H2=Green",
        "UpgEx_21H1=Green",
        "UpgEx_20H1=Green",
        "UpgEx_19H1=Green",
        "UpgEx_RS5=Green",
        "UpgradeAccepted=1",
        "UpgradeEligible=1",
        "UserInPlaceUpgrade=1",
        "VBSState=2",
        "Version_RS5=2000000000",
        "Win10CommercialAzureESUEligible=1",
        "Win10CommercialKeybasedESUEligible=1",
        "Win10CommercialW365ESUEligible=1",
        "Win10ConsumerESUStatus=3",
        "Win10ConsumerESUAY=9",
        "WuClientVer=" + build
    };
    
    std::string joined;
    for(size_t i = 0; i < attrs.size(); ++i) {
        if(i > 0) joined += "&";
        joined += attrs[i];
    }
    
    return xml_escape("E:" + joined);
}

std::string compose_fetch_update_request(
    const std::string& arch,
    const std::string& flight,
    const std::string& ring,
    const std::string& build,
    uint32_t sku,
    const std::string& release_type,
    const std::string& branch_val,
    const std::string& encrypted_data)
{
    std::string uuid = random_uuid_like();
    uint64_t now = unix_time();
    std::string created = w3c_time(now);
    std::string expires = w3c_time(now + 120);
    std::string cookie_expires = w3c_time(now + 604800);
    std::string device = uup_device();
    
    std::string branch = branch_val;
    if (branch == "auto") {
        branch = branch_from_build(build);
    }
    
    std::string main_product = "Client.OS.rs2";
    if (args_sku_is_server(sku)) {
        main_product = "Server.OS";
    } else if (sku == 180) {
        main_product = "WCOSDevice2.OS";
    } else if (sku == 184) {
        main_product = "WCOSDevice1.OS";
    } else if (sku == 189) {
        main_product = "WCOSDevice0.OS";
    } else if (sku == 210) {
        main_product = "WNC.OS";
    }
    
    std::vector<std::string> products;
    auto arches = split_arches(arch);
    for (const auto& curr_arch : arches) {
        products.push_back("PN=" + main_product + "." + curr_arch + "&Branch=" + branch + "&PrimaryOSProduct=1&Repairable=1&V=" + build + "&ReofferUpdate=1");
        products.push_back("PN=Adobe.Flash." + curr_arch + "&Repairable=1&V=0.0.0.0");
        products.push_back("PN=Microsoft.Edge.Stable." + curr_arch + "&Repairable=1&V=0.0.0.0");
        products.push_back("PN=Microsoft.NETFX." + curr_arch + "&V=0.0.0.0");
        products.push_back("PN=Windows.Autopilot." + curr_arch + "&Repairable=1&V=0.0.0.0");
        products.push_back("PN=Windows.AutopilotOOBE." + curr_arch + "&Repairable=1&V=0.0.0.0");
        products.push_back("PN=Windows.Appraiser." + curr_arch + "&Repairable=1&V=" + build);
        products.push_back("PN=Windows.AppraiserData." + curr_arch + "&Repairable=1&V=" + build);
        products.push_back("PN=Windows.EmergencyUpdate." + curr_arch + "&V=" + build);
        products.push_back("PN=Windows.FeatureExperiencePack." + curr_arch + "&Repairable=1&V=0.0.0.0");
        products.push_back("PN=Windows.ManagementOOBE." + curr_arch + "&IsWindowsManagementOOBE=1&Repairable=1&V=" + build);
        products.push_back("PN=Windows.OOBE." + curr_arch + "&IsWindowsOOBE=1&Repairable=1&V=" + build);
        products.push_back("PN=Windows.UpdateStackPackage." + curr_arch + "&Name=Update Stack Package&Repairable=1&V=" + build);
        products.push_back("PN=Hammer." + curr_arch + "&Source=UpdateOrchestrator&V=0.0.0.0");
        products.push_back("PN=MSRT." + curr_arch + "&Source=UpdateOrchestrator&V=0.0.0.0");
        products.push_back("PN=SedimentPack." + curr_arch + "&Source=UpdateOrchestrator&V=0.0.0.0");
        products.push_back("PN=UUS." + curr_arch + "&Source=UpdateOrchestrator&V=0.0.0.0");
    }
    
    std::string installed_ids_xml;
    for (auto id : INSTALLED_NON_LEAF_IDS) {
        installed_ids_xml += "<int>" + std::to_string(id) + "</int>";
    }
    
    std::string caller_attrib = xml_escape("E:Profile=AUv2&Acquisition=1&Interactive=1&IsSeeker=1&SheddingAware=1&Id=MoUpdateOrchestrator");
    
    std::string p_joined;
    for(size_t i = 0; i < products.size(); ++i) {
        if(i > 0) p_joined += ";";
        p_joined += products[i];
    }
    std::string escaped_products = xml_escape(p_joined);
    
    std::string device_attributes = compose_device_attributes(
        flight, ring, build, arch, sku, release_type, branch_val
    );
    
    const char* WU_CLIENT_ENDPOINT = "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured";
    
    std::string req = 
        "<s:Envelope xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
        "<s:Header>"
        "<a:Action s:mustUnderstand=\"1\">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates</a:Action>"
        "<a:MessageID>urn:uuid:" + uuid + "</a:MessageID>"
        "<a:To s:mustUnderstand=\"1\">" + std::string(WU_CLIENT_ENDPOINT) + "</a:To>"
        "<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        "<Timestamp xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><Created>" + created + "</Created><Expires>" + expires + "</Expires></Timestamp>"
        "<wuws:WindowsUpdateTicketsToken wsu:id=\"ClientMSA\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wuws=\"http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization\">"
        "<TicketType Name=\"MSA\" Version=\"1.0\" Policy=\"MBI_SSL\"><Device>" + device + "</Device></TicketType>"
        "</wuws:WindowsUpdateTicketsToken>"
        "</o:Security>"
        "</s:Header>"
        "<s:Body><SyncUpdates xmlns=\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService\">"
        "<cookie><Expiration>" + cookie_expires + "</Expiration><EncryptedData>" + encrypted_data + "</EncryptedData></cookie>"
        "<parameters><ExpressQuery>false</ExpressQuery><InstalledNonLeafUpdateIDs>" + installed_ids_xml + "</InstalledNonLeafUpdateIDs><OtherCachedUpdateIDs/><SkipSoftwareSync>false</SkipSoftwareSync><NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates><AlsoPerformRegularSync>true</AlsoPerformRegularSync><ComputerSpec/><ExtendedUpdateInfoParameters><XmlUpdateFragmentTypes><XmlUpdateFragmentType>Extended</XmlUpdateFragmentType><XmlUpdateFragmentType>LocalizedProperties</XmlUpdateFragmentType></XmlUpdateFragmentTypes><Locales><string>en-US</string></Locales></ExtendedUpdateInfoParameters><ClientPreferredLanguages/><ProductsParameters><SyncCurrentVersionOnly>false</SyncCurrentVersionOnly><DeviceAttributes>" + device_attributes + "</DeviceAttributes><CallerAttributes>" + caller_attrib + "</CallerAttributes><Products>" + escaped_products + "</Products></ProductsParameters></parameters>"
        "</SyncUpdates></s:Body>"
        "</s:Envelope>";
        
    return req;
}

} // namespace uup
