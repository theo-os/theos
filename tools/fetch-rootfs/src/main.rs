// Fetches Windows UUP packages from Windows Update (fe3.delivery.mp.microsoft.com).
// Implements the same SOAP protocol as the uupdump PHP API source.
//
// Flow:
//  1. GetCookie   → get encrypted session cookie
//  2. SyncUpdates → find the update ID + file list (hashes + names)
//  3. GetExtendedUpdateInfo2 → get per-hash download URLs
//  4. Download the packages we need, extract target files

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use clap::Parser;
use futures_util::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::Client;
use sha1::{Digest, Sha1};
use thiserror::Error;
use tokio::io::AsyncWriteExt;

// Windows Update SOAP endpoints
const WU_CLIENT: &str = "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx";
const WU_CLIENT_SECURED: &str =
    "https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured";
const WU_USERAGENT: &str = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.50";

// Packages patterns we care about for extracting the rootfs.
// Matched case-insensitively against the UUP package file names.
// UUP delivers localized install-image ESDs named like "professional_en-us.esd" or
// "core_en-us.esd". We only need the English neutral-N (no N-edition) images.
const PACKAGE_PATTERNS: &[&str] = &["professional_en-us.esd", "core_en-us.esd"];

#[derive(Parser, Debug)]
#[command(about = "Fetch Windows UUP packages via Windows Update SOAP API")]
struct Args {
    /// Directory to cache downloaded packages
    #[arg(long, default_value = ".uup-cache")]
    cache_dir: PathBuf,

    /// Output directory where target files are extracted
    #[arg(long)]
    output: PathBuf,

    /// Include-list file (same format as wimunpack --include-list)
    #[arg(long)]
    include_list: Option<PathBuf>,

    /// Windows build like "26100.0". Defaults to requesting the latest 26100.x.
    #[arg(long, default_value = "26100.0")]
    build: String,

    /// Architecture (amd64, arm64)
    #[arg(long, default_value = "amd64")]
    arch: String,

    /// Ring: RETAIL, RP, WIS, WIF, MSIT
    #[arg(long, default_value = "RETAIL")]
    ring: String,

    /// wimunpack binary path (for extracting downloaded packages)
    #[arg(long)]
    wimunpack: Option<PathBuf>,
}

#[derive(Debug, Error)]
enum FetchError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Windows Update error: {0}")]
    Wu(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("No update found for the requested build/ring")]
    NoUpdate,
    #[error("No matching packages found in update")]
    NoPackages,
}

// ── UUP file info (from SyncUpdates response) ─────────────────────────────────

#[derive(Debug, Clone)]
struct UupFile {
    name: String,
    sha1: Vec<u8>, // 20 bytes
    size: u64,
}

// ── Device token (uupDevice() from auths.php) ─────────────────────────────────

fn make_device_token() -> String {
    // Fixed header + 527 random bytes (1054 hex chars) + fixed trailer
    let header = hex_decode("13003002c377040014d5bcac7a66de0d50beddf9bba16c87edb9e019898000");
    let mut random = vec![0u8; 527];
    getrandom::fill(&mut random).expect("getrandom failed");
    let trailer = hex_decode("b401");

    let mut t_bytes = Vec::with_capacity(header.len() + 527 + trailer.len());
    t_bytes.extend_from_slice(&header);
    t_bytes.extend_from_slice(&random);
    t_bytes.extend_from_slice(&trailer);

    let t_value = B64.encode(&t_bytes);
    let data = format!("t={}&p=", t_value);

    // chunk_split(data, 1, "\0"): insert NUL after every byte, then base64
    let chunked: Vec<u8> = data.bytes().flat_map(|b| [b, 0u8]).collect();
    B64.encode(&chunked)
}

// ── Timestamp helpers ─────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn w3c_time(secs: u64) -> String {
    // Minimal UTC ISO 8601 formatter
    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400;
    // Gregorian calendar calculation from epoch
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}+00:00")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let dy = if leap { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: &[u64] = if leap {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for &md in month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn gen_uuid() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("getrandom failed");
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

// XML-escape a string (for embedding in SOAP body)
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ── SOAP XML composers (translated from requests.php) ─────────────────────────

fn compose_get_cookie_request(device: &str) -> String {
    let uuid = gen_uuid();
    let now = now_secs();
    let created = w3c_time(now);
    let expires = w3c_time(now + 120);

    format!(
        r#"<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie</a:Action>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:To s:mustUnderstand="1">{WU_CLIENT}</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <Created>{created}</Created>
                <Expires>{expires}</Expires>
            </Timestamp>
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL">
                    <Device>{device}</Device>
                </TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <GetCookie xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
            <oldCookie>
                <Expiration>{created}</Expiration>
            </oldCookie>
            <lastChange>{created}</lastChange>
            <currentTime>{created}</currentTime>
            <protocolVersion>2.0</protocolVersion>
        </GetCookie>
    </s:Body>
</s:Envelope>"#
    )
}

fn compose_device_attribs(build: &str, arch: &str, ring: &str, branch: &str, sku: u32) -> String {
    let now = now_secs();
    let (flt_ring, flt_branch, flight_enabled, is_retail) = match ring {
        "RETAIL" => ("Retail", "", 0, 1),
        "RP" => ("External", "ReleasePreview", 1, 0),
        "WIS" => ("External", "Beta", 1, 0),
        "WIF" => ("External", "Dev", 1, 0),
        "MSIT" => ("Internal", "MSIT", 1, 0),
        _ => ("External", "", 1, 0),
    };
    let attribs = [
        format!("App=WU_OS"),
        format!("AppVer={build}"),
        format!("AttrDataVer=352"),
        format!("AllowInPlaceUpgrade=1"),
        format!("AllowOptionalContent=1"),
        format!("AllowUpgradesWithUnsupportedTPMOrCPU=1"),
        format!("BlockFeatureUpdates=0"),
        format!("BranchReadinessLevel=CB"),
        format!("CIOptin=1"),
        format!("CurrentBranch={branch}"),
        format!("DataExpDateEpoch_GE25H2={}", now + 82800),
        format!("DataExpDateEpoch_GE24H2={}", now + 82800),
        format!("DataExpDateEpoch_NI22H2={}", now + 82800),
        format!("DefaultUserRegion=191"),
        format!("DeviceFamily=Windows.Desktop"),
        format!("DeviceInfoGatherSuccessful=1"),
        format!("FlightingBranchName={flt_branch}"),
        format!("FlightRing={flt_ring}"),
        format!("Free=gt64"),
        format!("GStatus_GE25H2=2"),
        format!("GStatus_GE24H2=2"),
        format!("GStatus_NI22H2=2"),
        format!("InstallDate=1438196400"),
        format!("InstallLanguage=en-US"),
        format!("InstallationType=Client"),
        format!("IsDeviceRetailDemo=0"),
        format!("IsFlightingEnabled={flight_enabled}"),
        format!("IsRetailOS={is_retail}"),
        format!("MediaVersion={build}"),
        format!("CloudPBR=1"),
        format!("DUScan=1"),
        format!("OEMModel=21F6CTO1WW"),
        format!("OEMName_Uncleaned=LENOVO"),
        format!("OSArchitecture={arch}"),
        format!("OSSkuId={sku}"),
        format!("OSUILocale=en-US"),
        format!("OSVersion={build}"),
        format!("ProcessorIdentifier=Intel64 Family 6 Model 186 Stepping 3"),
        format!("ProcessorManufacturer=GenuineIntel"),
        format!("ProductType=WinNT"),
        format!("ReleaseType=Production"),
        format!("SecureBootCapable=1"),
        format!("TelemetryLevel=3"),
        format!("TPMVersion=2"),
        format!("UpdateManagementGroup=2"),
        format!("UpdateOfferedDays=0"),
        format!("UpgEx_GE25H2=Green"),
        format!("UpgEx_GE24H2=Green"),
        format!("UpgEx_NI22H2=Green"),
        format!("UpgradeAccepted=1"),
        format!("UpgradeEligible=1"),
        format!("UserInPlaceUpgrade=1"),
        format!("VBSState=2"),
        format!("WuClientVer={build}"),
    ];
    xml_escape(&format!("E:{}", attribs.join("&")))
}

fn compose_sync_updates_request(
    device: &str,
    encrypted_data: &str,
    build: &str,  // e.g. "10.0.26100.0"
    arch: &str,   // e.g. "amd64"
    ring: &str,   // e.g. "RETAIL"
    branch: &str, // e.g. "ge_release"
    sku: u32,
) -> String {
    let uuid = gen_uuid();
    let now = now_secs();
    let created = w3c_time(now);
    let expires = w3c_time(now + 120);
    let cookie_expires = w3c_time(now + 604800);

    let device_attribs = compose_device_attribs(build, arch, ring, branch, sku);

    let main_product = format!(
        "PN=Client.OS.rs2.{arch}&Branch={branch}&PrimaryOSProduct=1&Repairable=1&V={build}&ReofferUpdate=1"
    );
    let products_list = [
        main_product.as_str(),
        &format!("PN=Adobe.Flash.{arch}&Repairable=1&V=0.0.0.0"),
        &format!("PN=Microsoft.Edge.Stable.{arch}&Repairable=1&V=0.0.0.0"),
        &format!("PN=Microsoft.NETFX.{arch}&V=0.0.0.0"),
        &format!(
            "PN=Windows.UpdateStackPackage.{arch}&Name=Update Stack Package&Repairable=1&V={build}"
        ),
    ];
    let products = xml_escape(&products_list.join(";"));

    let caller_attrib = xml_escape(
        "E:Profile=AUv2&Acquisition=1&Interactive=1&IsSeeker=1&SheddingAware=1&Id=MoUpdateOrchestrator",
    );

    // The large list of InstalledNonLeafUpdateIDs (from requests.php) tells WU what's already installed
    let non_leaf_ids = "1,2,3,10,11,17,19,2359974,2359977,5143990,5169043,5169044,5169047,\
        8788830,8806526,9125350,9154769,10809856,23110993,23110994,23110995,23110996,23110999,\
        23111000,23111001,23111002,23111003,23111004,24513870,28880263,30077688,30486944,\
        59830006,59830007,59830008,60484010,62450018,62450019,62450020,69801474,98959022,\
        98959023,98959024,98959025,98959026,105939029,105995585,106017178,107825194,117765322,\
        129905029,130040030,130040031,130040032,130040033,133399034,138372035,138372036,\
        139536037,139536038,139536039,139536040,142045136,158941041,158941042,158941043,\
        158941044,159776047,160733048,160733049,160733050,160733051,160733055,160733056,\
        161870057,161870058,161870059,296374060,316003061,326686062,326686063,327065581,\
        327072300,327072305,327100345";

    let non_leaf_xml: String = non_leaf_ids
        .split(',')
        .map(|id| format!("                    <int>{}</int>\n", id.trim()))
        .collect();

    format!(
        r#"<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates</a:Action>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:To s:mustUnderstand="1">{WU_CLIENT}</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <Created>{created}</Created>
                <Expires>{expires}</Expires>
            </Timestamp>
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL">
                    <Device>{device}</Device>
                </TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <SyncUpdates xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
            <cookie>
                <Expiration>{cookie_expires}</Expiration>
                <EncryptedData>{encrypted_data}</EncryptedData>
            </cookie>
            <parameters>
                <ExpressQuery>false</ExpressQuery>
                <InstalledNonLeafUpdateIDs>
{non_leaf_xml}                </InstalledNonLeafUpdateIDs>
                <OtherCachedUpdateIDs/>
                <SkipSoftwareSync>false</SkipSoftwareSync>
                <NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates>
                <AlsoPerformRegularSync>true</AlsoPerformRegularSync>
                <ComputerSpec/>
                <ExtendedUpdateInfoParameters>
                    <XmlUpdateFragmentTypes>
                        <XmlUpdateFragmentType>Extended</XmlUpdateFragmentType>
                        <XmlUpdateFragmentType>LocalizedProperties</XmlUpdateFragmentType>
                    </XmlUpdateFragmentTypes>
                    <Locales>
                        <string>en-US</string>
                    </Locales>
                </ExtendedUpdateInfoParameters>
                <ClientPreferredLanguages/>
                <ProductsParameters>
                    <SyncCurrentVersionOnly>false</SyncCurrentVersionOnly>
                    <DeviceAttributes>{device_attribs}</DeviceAttributes>
                    <CallerAttributes>{caller_attrib}</CallerAttributes>
                    <Products>{products}</Products>
                </ProductsParameters>
            </parameters>
        </SyncUpdates>
    </s:Body>
</s:Envelope>"#
    )
}

fn compose_file_get_request(
    device: &str,
    update_id: &str,
    rev: u32,
    build: &str,
    arch: &str,
    ring: &str,
    branch: &str,
    sku: u32,
) -> String {
    let uuid = gen_uuid();
    let now = now_secs();
    let created = w3c_time(now);
    let expires = w3c_time(now + 120);

    let device_attribs = compose_device_attribs(build, arch, ring, branch, sku);

    format!(
        r#"<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo2</a:Action>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:To s:mustUnderstand="1">{WU_CLIENT_SECURED}</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <Created>{created}</Created>
                <Expires>{expires}</Expires>
            </Timestamp>
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL">
                    <Device>{device}</Device>
                </TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <GetExtendedUpdateInfo2 xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
            <updateIDs>
                <UpdateIdentity>
                    <UpdateID>{update_id}</UpdateID>
                    <RevisionNumber>{rev}</RevisionNumber>
                </UpdateIdentity>
            </updateIDs>
            <infoTypes>
                <XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType>
                <XmlUpdateFragmentType>FileDecryption</XmlUpdateFragmentType>
                <XmlUpdateFragmentType>EsrpDecryptionInformation</XmlUpdateFragmentType>
                <XmlUpdateFragmentType>PiecesHashUrl</XmlUpdateFragmentType>
                <XmlUpdateFragmentType>BlockMapUrl</XmlUpdateFragmentType>
            </infoTypes>
            <deviceAttributes>{device_attribs}</deviceAttributes>
        </GetExtendedUpdateInfo2>
    </s:Body>
</s:Envelope>"#
    )
}

// ── Simple XML field extractors (regex-free, like PHP's preg_match approach) ─

fn xml_find_between<'a>(haystack: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = haystack.find(open)? + open.len();
    let end = haystack[start..].find(close)? + start;
    Some(&haystack[start..end])
}

fn xml_find_attr<'a>(element: &'a str, attr: &str) -> Option<&'a str> {
    let prefix = format!("{attr}=\"");
    let start = element.find(&prefix)? + prefix.len();
    let end = element[start..].find('"')? + start;
    Some(&element[start..end])
}

fn xml_decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

// ── SOAP call helpers ─────────────────────────────────────────────────────────

async fn soap_post(client: &Client, url: &str, body: &str) -> Result<String, FetchError> {
    let resp = client
        .post(url)
        .header("Content-Type", "application/soap+xml; charset=utf-8")
        .header("User-Agent", WU_USERAGENT)
        .body(body.to_string())
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;

    if !status.is_success() && status.as_u16() != 500 {
        return Err(FetchError::Wu(format!(
            "HTTP {status}: {}",
            &text[..text.len().min(200)]
        )));
    }
    Ok(text)
}

// ── Step 1: GetCookie ─────────────────────────────────────────────────────────

async fn get_cookie(client: &Client, device: &str) -> Result<String, FetchError> {
    let body = compose_get_cookie_request(device);
    let resp = soap_post(client, WU_CLIENT, &body).await?;
    let decoded = xml_decode_entities(&resp);

    xml_find_between(&decoded, "<EncryptedData>", "</EncryptedData>")
        .map(|s| s.to_string())
        .ok_or_else(|| {
            FetchError::Wu(format!(
                "no EncryptedData in GetCookie response (first 500 chars): {}",
                &resp[..resp.len().min(500)]
            ))
        })
}

// ── Step 2: SyncUpdates ───────────────────────────────────────────────────────

#[derive(Debug)]
struct SyncResult {
    update_id: String,
    rev: u32,
    files: Vec<UupFile>,
}

fn branch_from_build(build: &str) -> &'static str {
    let major: u32 = build
        .split('.')
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    match major {
        26100 | 26120 | 26200 | 26300 => "ge_release",
        25398 => "zn_release",
        22621 | 22631 | 22635 => "ni_release",
        22000 => "co_release",
        20348 | 20349 => "fe_release",
        19041..=19046 => "vb_release",
        17763 => "rs5_release",
        _ => "rs_prerelease",
    }
}

async fn sync_updates(
    client: &Client,
    device: &str,
    encrypted_data: &str,
    build: &str,
    arch: &str,
    ring: &str,
    sku: u32,
) -> Result<SyncResult, FetchError> {
    let full_build = if build.starts_with("10.0.") {
        build.to_string()
    } else {
        format!("10.0.{build}")
    };
    let branch = branch_from_build(&full_build);

    let body =
        compose_sync_updates_request(device, encrypted_data, &full_build, arch, ring, branch, sku);
    let resp = soap_post(client, WU_CLIENT, &body).await?;
    if std::env::var("WU_DEBUG").is_ok() {
        eprintln!("=== SyncUpdates response ===\n{resp}\n===");
    }
    let decoded = xml_decode_entities(&resp);

    parse_sync_result(&decoded, &full_build, arch, ring, branch, sku)
}

fn parse_sync_result(
    xml: &str,
    _build: &str,
    _arch: &str,
    _ring: &str,
    _branch: &str,
    _sku: u32,
) -> Result<SyncResult, FetchError> {
    // Find leaf UpdateInfo entries (IsLeaf=true)
    // The XML is on one line so we flatten it first
    let flat = xml.replace('\n', " ").replace('\r', "");

    // Find all <UpdateInfo>...</UpdateInfo> blocks
    let mut update_info_blocks = Vec::new();
    let mut search = flat.as_str();
    while let Some(start) = search.find("<UpdateInfo>") {
        let rest = &search[start..];
        if let Some(end) = rest.find("</UpdateInfo>") {
            update_info_blocks.push(&rest[..end + "</UpdateInfo>".len()]);
            search = &rest[end + "</UpdateInfo>".len()..];
        } else {
            break;
        }
    }

    // Filter to leaf updates
    let leaf_blocks: Vec<&str> = update_info_blocks
        .iter()
        .filter(|b| b.contains("<IsLeaf>true</IsLeaf>"))
        .copied()
        .collect();

    if leaf_blocks.is_empty() {
        return Err(FetchError::NoUpdate);
    }

    // Use the first leaf update
    let block = leaf_blocks[0];

    // Extract numeric ID for matching Update entries
    let num_id = xml_find_between(block, "<ID>", "</ID>")
        .ok_or_else(|| FetchError::Wu("no <ID> in UpdateInfo".into()))?;

    // Collect all <Update>...</Update> blocks (they appear after <UpdateInfo> in the response).
    // Find the one with matching ID that also contains <Files> (the file-list block).
    let id_marker = format!("<ID>{num_id}</ID>");
    let mut update_block_with_files: Option<&str> = None;
    let mut search_u = flat.as_str();
    while let Some(us) = search_u.find("<Update>") {
        let rest = &search_u[us..];
        let ue = rest.find("</Update>").unwrap_or(rest.len());
        let candidate = &rest[..ue];
        if candidate.contains(&id_marker) && candidate.contains("<Files>") {
            update_block_with_files = Some(candidate);
            break;
        }
        search_u = &rest[ue.saturating_add(9)..];
        if search_u.is_empty() {
            break;
        }
    }
    let update_block = update_block_with_files
        .ok_or_else(|| FetchError::Wu(format!("no <Update> with <Files> for ID {num_id}")))?;

    // Extract UpdateID and RevisionNumber from ExtendedProperties or from UpdateInfo
    let update_id = xml_find_attr(block, "UpdateID")
        .or_else(|| xml_find_between(block, "<UpdateID>", "</UpdateID>"))
        .ok_or_else(|| FetchError::Wu("no UpdateID in leaf block".into()))?
        .to_string();

    let rev_str = xml_find_attr(block, "RevisionNumber")
        .or_else(|| xml_find_between(block, "<RevisionNumber>", "</RevisionNumber>"))
        .unwrap_or("1");
    let rev: u32 = rev_str.parse().unwrap_or(1);

    // Parse <Files> section
    let files_section = xml_find_between(update_block, "<Files>", "</Files>").unwrap_or("");

    let mut files = Vec::new();
    let mut rest = files_section;
    while let Some(file_start) = rest.find("<File ") {
        let file_rest = &rest[file_start..];
        let file_end = file_rest
            .find("/>")
            .or_else(|| file_rest.find("</File>"))
            .unwrap_or(file_rest.len() - 1);
        let file_elem = &file_rest[..file_end + 2];

        if let (Some(name), Some(digest), Some(size_str)) = (
            xml_find_attr(file_elem, "FileName"),
            xml_find_attr(file_elem, "Digest"),
            xml_find_attr(file_elem, "Size"),
        ) {
            let sha1_bytes = B64.decode(digest).unwrap_or_default();
            let size: u64 = size_str.parse().unwrap_or(0);
            // Clean name (strip cabs_ prefix like uupCleanName does)
            let clean_name = name
                .trim_start_matches("cabs_")
                .trim_start_matches("metadataesd_")
                .to_ascii_lowercase();
            files.push(UupFile {
                name: clean_name,
                sha1: sha1_bytes,
                size,
            });
        }

        rest = &file_rest[file_end + 2..];
    }

    eprintln!(
        "info: found update {} rev={} with {} files",
        &update_id[..8],
        rev,
        files.len()
    );

    Ok(SyncResult {
        update_id,
        rev,
        files,
    })
}

// ── Step 3: GetExtendedUpdateInfo2 ────────────────────────────────────────────

async fn get_download_urls(
    client: &Client,
    device: &str,
    update_id: &str,
    rev: u32,
    build: &str,
    arch: &str,
    ring: &str,
    sku: u32,
) -> Result<HashMap<Vec<u8>, String>, FetchError> {
    let full_build = if build.starts_with("10.0.") {
        build.to_string()
    } else {
        format!("10.0.{build}")
    };
    let branch = branch_from_build(&full_build);

    let body =
        compose_file_get_request(device, update_id, rev, &full_build, arch, ring, branch, sku);
    let resp = soap_post(client, WU_CLIENT_SECURED, &body).await?;
    if std::env::var("WU_DEBUG").is_ok() {
        eprintln!(
            "=== GetExtendedUpdateInfo2 response ===\n{}\n===",
            &resp[..resp.len().min(4000)]
        );
    }
    let decoded = xml_decode_entities(&resp);

    let mut urls: HashMap<Vec<u8>, String> = HashMap::new();
    let mut rest = decoded.as_str();
    while let Some(loc_start) = rest.find("<FileLocation>") {
        let loc_rest = &rest[loc_start..];
        if let Some(loc_end) = loc_rest.find("</FileLocation>") {
            let elem = &loc_rest[..loc_end + "</FileLocation>".len()];
            if let (Some(digest), Some(url)) = (
                xml_find_between(elem, "<FileDigest>", "</FileDigest>"),
                xml_find_between(elem, "<Url>", "</Url>"),
            ) {
                let sha1 = B64.decode(digest).unwrap_or_default();
                urls.insert(sha1, url.to_string());
            }
            rest = &loc_rest[loc_end + "</FileLocation>".len()..];
        } else {
            break;
        }
    }

    eprintln!("info: got {} download URLs", urls.len());
    Ok(urls)
}

// ── Download helper ───────────────────────────────────────────────────────────

async fn download_file(
    client: &Client,
    url: &str,
    dest: &Path,
    size: u64,
    mp: &MultiProgress,
) -> Result<(), FetchError> {
    let pb = mp.add(ProgressBar::new(size));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:38.cyan/blue}] {bytes}/{total_bytes} {msg}")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_message(
        dest.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
    );

    let tmp = dest.with_extension("part");
    let resp = client.get(url).send().await?.error_for_status()?;
    let mut file = tokio::fs::File::create(&tmp).await?;
    let mut stream = resp.bytes_stream();
    let mut downloaded = 0u64;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        pb.set_position(downloaded);
    }
    file.flush().await?;
    drop(file);
    pb.finish_and_clear();

    tokio::fs::rename(&tmp, dest).await?;
    Ok(())
}

async fn verify_sha1(path: &Path, expected: &[u8]) -> Result<bool, FetchError> {
    let data = tokio::fs::read(path).await?;
    let mut h = Sha1::new();
    h.update(&data);
    Ok(h.finalize().as_slice() == expected)
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("error: {e}");
        let mut src: &dyn std::error::Error = &e;
        while let Some(cause) = src.source() {
            eprintln!("  caused by: {cause}");
            src = cause;
        }
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), FetchError> {
    tokio::fs::create_dir_all(&args.cache_dir).await?;
    tokio::fs::create_dir_all(&args.output).await?;

    // Microsoft's WU endpoint uses a cert signed by "Microsoft Update Secure Server CA 2.1"
    // which is not in the standard Mozilla/system CA bundles. Skip verification; the
    // endpoint is a fixed well-known Microsoft hostname, not user-supplied.
    let client = Client::builder()
        .user_agent(WU_USERAGENT)
        .danger_accept_invalid_certs(true)
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(300))
        .build()?;

    let device = make_device_token();
    let mp = MultiProgress::new();
    let spinner_style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
        .unwrap()
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

    // Step 1: cookie
    let sp = mp.add(ProgressBar::new_spinner());
    sp.set_style(spinner_style.clone());
    sp.set_message("contacting Windows Update...");
    sp.enable_steady_tick(std::time::Duration::from_millis(80));
    let cookie = get_cookie(&client, &device).await?;
    sp.finish_and_clear();

    // Step 2: sync updates (slow — WU returns ~6MB of XML)
    let sp = mp.add(ProgressBar::new_spinner());
    sp.set_style(spinner_style.clone());
    sp.set_message(format!(
        "syncing update catalogue for build {} {}...",
        args.build, args.ring
    ));
    sp.enable_steady_tick(std::time::Duration::from_millis(80));
    let sync = sync_updates(
        &client,
        &device,
        &cookie,
        &args.build,
        &args.arch,
        &args.ring,
        48,
    )
    .await?;
    sp.finish_and_clear();

    // Filter to packages we need
    let wanted: Vec<&UupFile> = sync
        .files
        .iter()
        .filter(|f| {
            let nl = f.name.to_ascii_lowercase();
            PACKAGE_PATTERNS.iter().any(|p| nl.contains(p))
        })
        .collect();

    if wanted.is_empty() {
        return Err(FetchError::NoPackages);
    }

    eprintln!(
        "info: {} package(s) selected (of {} total files)",
        wanted.len(),
        sync.files.len()
    );
    for f in &wanted {
        eprintln!("  {}", f.name);
    }

    // Step 3: get download URLs
    let sp = mp.add(ProgressBar::new_spinner());
    sp.set_style(spinner_style.clone());
    sp.set_message("fetching download URLs...");
    sp.enable_steady_tick(std::time::Duration::from_millis(80));
    let urls = get_download_urls(
        &client,
        &device,
        &sync.update_id,
        sync.rev,
        &args.build,
        &args.arch,
        &args.ring,
        48,
    )
    .await?;
    sp.finish_and_clear();

    // Step 4: download packages (in parallel with progress)
    let mut to_extract: Vec<PathBuf> = Vec::new();

    let mut download_tasks = Vec::new();
    for file in &wanted {
        let url = match urls.get(&file.sha1) {
            Some(u) => u.clone(),
            None => {
                eprintln!("warn: no URL for {}", file.name);
                continue;
            }
        };
        let dest = args.cache_dir.join(&file.name);
        to_extract.push(dest.clone());

        let client2 = client.clone();
        let mp2 = mp.clone();
        let size = file.size;
        let sha1 = file.sha1.clone();
        download_tasks.push(tokio::spawn(async move {
            if dest.exists() {
                if verify_sha1(&dest, &sha1).await.unwrap_or(false) {
                    eprintln!(
                        "info: using cached {}",
                        dest.file_name().unwrap_or_default().to_string_lossy()
                    );
                    return Ok::<PathBuf, FetchError>(dest);
                }
            }
            download_file(&client2, &url, &dest, size, &mp2).await?;
            Ok(dest)
        }));
    }

    let mut downloaded = Vec::new();
    for task in download_tasks {
        match task.await {
            Ok(Ok(path)) => downloaded.push(path),
            Ok(Err(e)) => eprintln!("warn: download failed: {e}"),
            Err(e) => eprintln!("warn: task error: {e}"),
        }
    }

    if downloaded.is_empty() {
        return Err(FetchError::Wu("no packages downloaded successfully".into()));
    }

    // Step 5: extract target files from each package WIM using wimunpack
    let include_list = args.include_list.as_deref();
    let wimunpack = args.wimunpack.unwrap_or_else(|| PathBuf::from("wimunpack"));

    let pb = ProgressBar::new(downloaded.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{pos}/{len}] extracting {msg}")
            .unwrap(),
    );

    for pkg_path in &downloaded {
        pb.set_message(
            pkg_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        );

        let mut cmd = std::process::Command::new(&wimunpack);
        cmd.arg("--esd")
            .arg(pkg_path)
            .arg("--output")
            .arg(&args.output);

        if let Some(list) = include_list {
            cmd.arg("--include-list").arg(list);
        }

        match cmd.output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                // Package doesn't contain the files we need — that's fine
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.contains("no files extracted") && !stderr.contains("not found") {
                    eprintln!(
                        "warn: wimunpack on {}: {}",
                        pkg_path.display(),
                        stderr.trim()
                    );
                }
            }
            Err(e) => eprintln!("warn: could not run wimunpack: {e}"),
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    eprintln!("info: extraction complete → {}", args.output.display());
    Ok(())
}
