use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use flate2::read::DeflateDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{Cursor, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, sleep};

const WU_CLIENT_ENDPOINT: &str =
    "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx";
const WU_CLIENT_SECURED_ENDPOINT: &str =
    "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured";
const WU_USER_AGENT: &str = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.50";

const INSTALLED_NON_LEAF_IDS: &[u32] = &[
    1,
    10,
    105_939_029,
    105_995_585,
    106_017_178,
    107_825_194,
    10_809_856,
    11,
    117_765_322,
    129_905_029,
    130_040_030,
    130_040_031,
    130_040_032,
    130_040_033,
    133_399_034,
    138_372_035,
    138_372_036,
    139_536_037,
    139_536_038,
    139_536_039,
    139_536_040,
    142_045_136,
    158_941_041,
    158_941_042,
    158_941_043,
    158_941_044,
    159_776_047,
    160_733_048,
    160_733_049,
    160_733_050,
    160_733_051,
    160_733_055,
    160_733_056,
    161_870_057,
    161_870_058,
    161_870_059,
    17,
    19,
    2,
    23_110_993,
    23_110_994,
    23_110_995,
    23_110_996,
    23_110_999,
    23_111_000,
    23_111_001,
    23_111_002,
    23_111_003,
    23_111_004,
    2_359_974,
    2_359_977,
    24_513_870,
    28_880_263,
    296_374_060,
    3,
    30_077_688,
    30_486_944,
    5_143_990,
    5_169_043,
    5_169_044,
    5_169_047,
    59_830_006,
    59_830_007,
    59_830_008,
    60_484_010,
    62_450_018,
    62_450_019,
    62_450_020,
    69_801_474,
    8_788_830,
    8_806_526,
    9_125_350,
    9_154_769,
    98_959_022,
    98_959_023,
    98_959_024,
    98_959_025,
    98_959_026,
];

#[derive(Parser, Debug)]
#[command(about = "Fetch Windows install WIM/ESD directly from Microsoft UUP endpoints")]
struct Args {
    #[arg(long, default_value = "amd64")]
    arch: String,

    #[arg(long, default_value = "WIF")]
    ring: String,

    #[arg(long, default_value = "Active")]
    flight: String,

    #[arg(long, default_value = "29565.1000")]
    build: String,

    #[arg(long, default_value_t = 48)]
    sku: u32,

    #[arg(long, default_value = "Production")]
    release_type: String,

    #[arg(long, default_value = "auto")]
    branch: String,

    #[arg(long)]
    update_id: Option<String>,

    #[arg(long)]
    revision: Option<u32>,

    #[arg(long, default_value = ".uup-cache")]
    output_dir: PathBuf,
}

#[derive(Clone, Debug)]
struct UpdateFileInfo {
    name: String,
    size: u64,
}

#[derive(Clone, Debug)]
struct ChosenUpdate {
    update_id: String,
    revision: u32,
    files: HashMap<String, UpdateFileInfo>,
}

#[derive(Clone, Debug)]
struct DownloadLocation {
    sha1_hex: String,
    url: String,
}

#[derive(Clone, Debug)]
struct DownloadCandidate {
    name: String,
    size: u64,
    url: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    rustls_graviola::default_provider()
        .install_default()
        .unwrap();

    let args = Args::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let out_path = runtime.block_on(async_main(args))?;
    println!("{}", out_path.display());
    Ok(())
}

async fn async_main(args: Args) -> Result<PathBuf, Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .http1_only()
        .http1_title_case_headers()
        .build()?;
    let progress = ProgressUi::new();
    let debug = std::env::var_os("UUP_DEBUG").is_some();

    let cookie_response = progress
        .spinner("contacting Windows Update for cookie", async {
            post_soap_with_retry(
                &client,
                WU_CLIENT_ENDPOINT,
                compose_get_cookie_request().as_str(),
            )
            .await
        })
        .await?;
    let cookie_xml = xml_unescape(&cookie_response);
    let encrypted_data = extract_tag_text(&cookie_xml, "EncryptedData")
        .ok_or("GetCookie response missing EncryptedData")?;

    let build = normalize_build(&args.build)?;
    let branch_candidates = build_branch_candidates(args.branch.as_str(), build.as_str());
    let mut fallback_candidate: Option<(ChosenUpdate, String)> = None;
    let mut chosen_pair: Option<(ChosenUpdate, String)> = None;
    let mut chosen_sync_xml: Option<String> = None;
    let mut last_error: Option<String> = None;

    for branch_candidate in &branch_candidates {
        if debug {
            eprintln!("debug: probing branch={branch_candidate}");
        }

        let sync_request = compose_fetch_update_request(
            args.arch.as_str(),
            args.flight.as_str(),
            args.ring.as_str(),
            build.as_str(),
            args.sku,
            args.release_type.as_str(),
            branch_candidate.as_str(),
            encrypted_data.as_str(),
        );

        let sync_response = progress
            .spinner("fetching available updates", async {
                post_soap_with_retry(&client, WU_CLIENT_ENDPOINT, sync_request.as_str()).await
            })
            .await?;
        let sync_xml = xml_unescape(&sync_response);

        match progress
            .spinner("selecting update payload", async {
                select_update(
                    &sync_xml,
                    args.update_id.as_deref(),
                    args.revision,
                    args.arch.as_str(),
                )
            })
            .await
        {
            Ok(candidate) => {
                if has_wim_or_esd_files(&candidate.files) {
                    chosen_pair = Some((candidate, branch_candidate.clone()));
                    chosen_sync_xml = Some(sync_xml.clone());
                    break;
                }
                if fallback_candidate.is_none() {
                    fallback_candidate = Some((candidate, branch_candidate.clone()));
                    chosen_sync_xml = Some(sync_xml.clone());
                }
            }
            Err(error) => {
                last_error = Some(error.to_string());
            }
        }
    }

    let (chosen, selected_branch) = if let Some(pair) = chosen_pair.or(fallback_candidate) {
        pair
    } else {
        return Err(last_error
            .unwrap_or_else(|| "no matching update found across branch candidates".to_string())
            .into());
    };

    if debug {
        eprintln!(
            "debug: selected branch={} chosen_files={} has_wim_or_esd={}",
            selected_branch,
            chosen.files.len(),
            has_wim_or_esd_files(&chosen.files)
        );
    }

    let ext_request = compose_file_get_request(
        chosen.update_id.as_str(),
        chosen.revision,
        args.flight.as_str(),
        args.ring.as_str(),
        build.as_str(),
        args.arch.as_str(),
        args.sku,
        args.release_type.as_str(),
        selected_branch.as_str(),
    );
    let ext_response = progress
        .spinner("fetching download URLs", async {
            post_soap_with_retry(&client, WU_CLIENT_SECURED_ENDPOINT, ext_request.as_str()).await
        })
        .await?;
    let ext_xml = xml_unescape(&ext_response);
    let locations = parse_file_locations(&ext_xml)?;

    if debug {
        eprintln!(
            "debug: chosen files={} file locations={}",
            chosen.files.len(),
            locations.len()
        );
    }

    let mut candidates = Vec::new();
    let mut matched_digests = 0usize;
    for location in &locations {
        if let Some(info) = chosen.files.get(&location.sha1_hex) {
            matched_digests += 1;
            let lower = info.name.to_ascii_lowercase();
            if lower.ends_with(".wim") || lower.ends_with(".esd") {
                candidates.push(DownloadCandidate {
                    name: info.name.clone(),
                    size: info.size,
                    url: location.url.clone(),
                });
            }
        }
    }

    if debug {
        eprintln!(
            "debug: matched digests={} install candidates={}",
            matched_digests,
            candidates.len()
        );
    }

    let mut selected = if let Some(selected) = pick_install_image(&candidates) {
        DownloadCandidate {
            name: selected.name.clone(),
            size: selected.size,
            url: selected.url.clone(),
        }
    } else {
        let Some(sync_xml) = chosen_sync_xml.as_ref() else {
            return Err("could not find install.wim/install.esd in UUP file list".into());
        };
        let fallback = progress
            .spinner("probing update payloads", async {
                probe_install_candidate_from_update_infos(
                    sync_xml,
                    &client,
                    build.as_str(),
                    args.arch.as_str(),
                    args.ring.as_str(),
                    args.flight.as_str(),
                    args.sku,
                    args.release_type.as_str(),
                    selected_branch.as_str(),
                )
                .await
            })
            .await?;
        fallback.ok_or("could not find install.wim/install.esd in UUP file list")?
    };

    if is_cab_file(selected.name.as_str()) {
        fs::create_dir_all(&args.output_dir)?;
        let cab_path = args
            .output_dir
            .join(sanitize_filename(selected.name.as_str()));
        if !cab_path.exists() {
            progress
                .download(
                    &client,
                    selected.url.as_str(),
                    &cab_path,
                    selected.size,
                    selected.name.as_str(),
                )
                .await?;
        }

        let cab_hints = progress
            .spinner("scanning cab for install media hints", async {
                find_install_names_from_cab(&cab_path)
            })
            .await?;

        if cab_hints.is_empty() {
            return Err("cab did not contain install.wim/install.esd references".into());
        }

        let Some(sync_xml) = chosen_sync_xml.as_ref() else {
            return Err("cab scan needs SyncUpdates XML".into());
        };

        let cab_candidate = progress
            .spinner("probing updates for install media", async {
                probe_install_candidate_by_name(
                    sync_xml,
                    &client,
                    build.as_str(),
                    args.arch.as_str(),
                    args.ring.as_str(),
                    args.flight.as_str(),
                    args.sku,
                    args.release_type.as_str(),
                    selected_branch.as_str(),
                    &cab_hints,
                )
                .await
            })
            .await?;

        if let Some(candidate) = cab_candidate {
            selected = candidate;
        } else {
            return Err(format!(
                "cab hints did not match any update file URLs ({})",
                format_hint_list(&cab_hints)
            )
            .into());
        }
    }

    fs::create_dir_all(&args.output_dir)?;
    let out_path = args
        .output_dir
        .join(sanitize_filename(selected.name.as_str()));
    progress
        .download(
            &client,
            selected.url.as_str(),
            &out_path,
            selected.size,
            selected.name.as_str(),
        )
        .await?;
    Ok(out_path)
}

fn build_branch_candidates(branch: &str, build: &str) -> Vec<String> {
    if !branch.eq_ignore_ascii_case("auto") {
        return vec![branch.to_owned()];
    }

    let mut out = Vec::new();
    for candidate in [
        branch_from_build(build),
        "rs_prerelease".to_string(),
        "ge_prerelease".to_string(),
        "br_release".to_string(),
        "ge_release".to_string(),
        "ni_release".to_string(),
    ] {
        if !out.iter().any(|item| item == &candidate) {
            out.push(candidate);
        }
    }

    out
}

async fn probe_install_candidate_from_update_infos(
    sync_xml: &str,
    client: &reqwest::Client,
    build: &str,
    arch: &str,
    ring: &str,
    flight: &str,
    sku: u32,
    release_type: &str,
    branch: &str,
) -> Result<Option<DownloadCandidate>, Box<dyn Error>> {
    let mut identities = Vec::new();
    let mut seen = HashMap::new();

    for info in find_all_tag_blocks(sync_xml, "UpdateInfo") {
        let Some(update_id) = extract_attr(info.as_str(), "UpdateID") else {
            continue;
        };
        let revision = extract_attr(info.as_str(), "RevisionNumber")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1);
        let update_type = extract_attr(info.as_str(), "UpdateType").unwrap_or_default();
        let is_category = update_type.eq_ignore_ascii_case("Category");

        let key = format!("{update_id}:{revision}");
        if seen.insert(key, ()).is_some() {
            continue;
        }

        identities.push((is_category, update_id, revision));
    }

    identities.sort_by_key(|(is_category, _, _)| *is_category);

    let mut best: Option<DownloadCandidate> = None;

    for (is_category, update_id, revision) in identities {
        if is_category && best.is_some() {
            continue;
        }

        let ext_request = compose_file_get_request(
            update_id.as_str(),
            revision,
            flight,
            ring,
            build,
            arch,
            sku,
            release_type,
            branch,
        );
        let ext_response = post_soap_with_retry(client, WU_CLIENT_SECURED_ENDPOINT, &ext_request)
            .await
            .ok();
        let Some(ext_response) = ext_response else {
            continue;
        };

        let ext_xml = xml_unescape(&ext_response);
        let locations = parse_file_locations(&ext_xml).unwrap_or_default();
        if locations.is_empty() {
            continue;
        }

        for location in locations {
            let Some(file_name) = filename_from_url(location.url.as_str()) else {
                continue;
            };
            let lower = file_name.to_ascii_lowercase();
            if !lower.ends_with(".wim") && !lower.ends_with(".esd") {
                continue;
            }

            let candidate = DownloadCandidate {
                name: file_name,
                size: 0,
                url: location.url,
            };

            if looks_like_install_image(candidate.name.as_str()) {
                return Ok(Some(candidate));
            }
            if best.is_none() {
                best = Some(candidate);
            }
        }
    }

    Ok(best)
}

fn filename_from_url(url: &str) -> Option<String> {
    let trimmed = url.split('?').next().unwrap_or(url);
    let segment = trimmed.rsplit('/').next()?;
    if segment.is_empty() {
        None
    } else {
        Some(segment.to_string())
    }
}

fn looks_like_install_image(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.contains("install") && lower.ends_with(".wim"))
        || (lower.contains("install") && lower.ends_with(".esd"))
}

fn is_cab_file(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".cab")
}

fn format_hint_list(hints: &[String]) -> String {
    let mut items = hints.iter().take(6).cloned().collect::<Vec<_>>();
    if hints.len() > items.len() {
        items.push("...".to_string());
    }
    items.join(", ")
}

async fn probe_install_candidate_by_name(
    sync_xml: &str,
    client: &reqwest::Client,
    build: &str,
    arch: &str,
    ring: &str,
    flight: &str,
    sku: u32,
    release_type: &str,
    branch: &str,
    names: &[String],
) -> Result<Option<DownloadCandidate>, Box<dyn Error>> {
    if names.is_empty() {
        return Ok(None);
    }

    let wanted: HashSet<String> = names.iter().map(|name| name.to_ascii_lowercase()).collect();

    let mut identities = Vec::new();
    let mut seen = HashMap::new();

    for info in find_all_tag_blocks(sync_xml, "UpdateInfo") {
        let Some(update_id) = extract_attr(info.as_str(), "UpdateID") else {
            continue;
        };
        let revision = extract_attr(info.as_str(), "RevisionNumber")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1);
        let update_type = extract_attr(info.as_str(), "UpdateType").unwrap_or_default();
        let is_category = update_type.eq_ignore_ascii_case("Category");

        let key = format!("{update_id}:{revision}");
        if seen.insert(key, ()).is_some() {
            continue;
        }

        identities.push((is_category, update_id, revision));
    }

    identities.sort_by_key(|(is_category, _, _)| *is_category);

    let mut best: Option<DownloadCandidate> = None;

    for (is_category, update_id, revision) in identities {
        if is_category && best.is_some() {
            continue;
        }

        let ext_request = compose_file_get_request(
            update_id.as_str(),
            revision,
            flight,
            ring,
            build,
            arch,
            sku,
            release_type,
            branch,
        );
        let ext_response = post_soap_with_retry(client, WU_CLIENT_SECURED_ENDPOINT, &ext_request)
            .await
            .ok();
        let Some(ext_response) = ext_response else {
            continue;
        };

        let ext_xml = xml_unescape(&ext_response);
        let locations = parse_file_locations(&ext_xml).unwrap_or_default();
        if locations.is_empty() {
            continue;
        }

        for location in locations {
            let Some(file_name) = filename_from_url(location.url.as_str()) else {
                continue;
            };
            if !matches_install_name(file_name.as_str(), &wanted) {
                continue;
            }

            let candidate = DownloadCandidate {
                name: file_name,
                size: 0,
                url: location.url,
            };

            if looks_like_install_image(candidate.name.as_str()) {
                return Ok(Some(candidate));
            }
            if best.is_none() {
                best = Some(candidate);
            }
        }
    }

    Ok(best)
}

fn matches_install_name(filename: &str, wanted: &HashSet<String>) -> bool {
    let lower = filename.to_ascii_lowercase();
    if wanted.contains(&lower) {
        return true;
    }

    wanted.iter().any(|hint| lower.ends_with(hint))
}

fn find_install_names_from_cab(path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let cab = parse_cab_archive(&bytes)?;
    let mut names = HashSet::new();

    for file in &cab.files {
        if looks_like_install_file_name(file.name.as_str()) {
            names.insert(file.name.to_ascii_lowercase());
        }
    }

    let mut folder_cache: HashMap<u16, Vec<u8>> = HashMap::new();
    for file in &cab.files {
        if !should_scan_cab_entry(file) {
            continue;
        }

        let folder_index = file.folder_index;
        if !folder_cache.contains_key(&folder_index) {
            let folder = cab
                .folders
                .get(folder_index as usize)
                .ok_or("cab folder index out of range")?;
            let data = decompress_cab_folder(&bytes, folder, cab.cb_cfdata)?;
            folder_cache.insert(folder_index, data);
        }

        let data = folder_cache
            .get(&folder_index)
            .ok_or("cab folder data missing")?;
        let start = file.offset as usize;
        let end = start.saturating_add(file.size as usize);
        if end > data.len() {
            continue;
        }

        for hint in scan_for_install_names(&data[start..end]) {
            names.insert(hint.to_ascii_lowercase());
        }
    }

    Ok(names.into_iter().collect())
}

fn looks_like_install_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".wim") || lower.ends_with(".esd")
}

fn should_scan_cab_entry(file: &CabFile) -> bool {
    if file.size == 0 || file.size > 16 * 1024 * 1024 {
        return false;
    }
    let lower = file.name.to_ascii_lowercase();
    lower.ends_with(".xml")
        || lower.ends_with(".txt")
        || lower.ends_with(".ini")
        || lower.ends_with(".mum")
        || lower.ends_with(".manifest")
        || lower.ends_with(".cfg")
}

fn scan_for_install_names(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx + 4 <= data.len() {
        let slice = &data[idx..idx + 4];
        if eq_ascii_case(slice, b".wim") || eq_ascii_case(slice, b".esd") {
            let start = scan_token_start(data, idx);
            let end = scan_token_end(data, idx + 4);
            if end > start && end - start <= 260 {
                if let Ok(value) = std::str::from_utf8(&data[start..end]) {
                    out.push(value.to_string());
                }
            }
            idx += 4;
        } else {
            idx += 1;
        }
    }
    out
}

fn scan_token_start(data: &[u8], mut idx: usize) -> usize {
    while idx > 0 {
        let prev = data[idx - 1];
        if !is_token_char(prev) {
            break;
        }
        idx -= 1;
    }
    idx
}

fn scan_token_end(data: &[u8], mut idx: usize) -> usize {
    while idx < data.len() {
        let b = data[idx];
        if !is_token_char(b) {
            break;
        }
        idx += 1;
    }
    idx
}

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b'\\' | b':')
}

fn eq_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
}

struct CabArchive {
    folders: Vec<CabFolder>,
    files: Vec<CabFile>,
    cb_cfdata: usize,
}

struct CabFolder {
    coff_cab_start: u32,
    c_cfdata: u16,
    type_compress: u16,
}

struct CabFile {
    name: String,
    folder_index: u16,
    offset: u32,
    size: u32,
}

fn parse_cab_archive(bytes: &[u8]) -> Result<CabArchive, Box<dyn Error>> {
    if bytes.len() < 36 {
        return Err("cab file too small".into());
    }
    if &bytes[..4] != b"MSCF" {
        return Err("cab file missing MSCF signature".into());
    }

    let coff_files = read_u32_le_at(bytes, 16) as usize;
    let c_folders = read_u16_le_at(bytes, 26) as usize;
    let c_files = read_u16_le_at(bytes, 28) as usize;
    let flags = read_u16_le_at(bytes, 30);

    let mut offset = 36usize;
    let mut cb_cfheader = 0usize;
    let mut cb_cffolder = 0usize;
    let mut cb_cfdata = 0usize;

    if flags & 0x0004 != 0 {
        cb_cfheader = read_u16_le_at(bytes, offset) as usize;
        offset += 2;
        cb_cffolder = read_u16_le_at(bytes, offset) as usize;
        offset += 2;
        cb_cfdata = read_u16_le_at(bytes, offset) as usize;
        offset += 2;
    }

    offset = offset.saturating_add(cb_cfheader);

    if flags & 0x0001 != 0 {
        let (next, _) = read_cstring(bytes, offset)?;
        let (next, _) = read_cstring(bytes, next)?;
        offset = next;
    }

    if flags & 0x0002 != 0 {
        let (next, _) = read_cstring(bytes, offset)?;
        let (next, _) = read_cstring(bytes, next)?;
        offset = next;
    }

    let mut folders = Vec::with_capacity(c_folders);
    for _ in 0..c_folders {
        if offset + 8 > bytes.len() {
            return Err("cab folder table truncated".into());
        }
        let coff_cab_start = read_u32_le_at(bytes, offset);
        offset += 4;
        let c_cfdata = read_u16_le_at(bytes, offset);
        offset += 2;
        let type_compress = read_u16_le_at(bytes, offset);
        offset += 2;
        offset = offset.saturating_add(cb_cffolder);
        folders.push(CabFolder {
            coff_cab_start,
            c_cfdata,
            type_compress,
        });
    }

    let mut files = Vec::with_capacity(c_files);
    let mut file_offset = coff_files;
    for _ in 0..c_files {
        if file_offset + 16 > bytes.len() {
            return Err("cab file table truncated".into());
        }
        let size = read_u32_le_at(bytes, file_offset);
        file_offset += 4;
        let offset_in_folder = read_u32_le_at(bytes, file_offset);
        file_offset += 4;
        let folder_index = read_u16_le_at(bytes, file_offset);
        file_offset += 2;
        file_offset += 6;
        let (next, name) = read_cstring(bytes, file_offset)?;
        file_offset = next;
        files.push(CabFile {
            name,
            folder_index,
            offset: offset_in_folder,
            size,
        });
    }

    Ok(CabArchive {
        folders,
        files,
        cb_cfdata,
    })
}

fn read_cstring(bytes: &[u8], offset: usize) -> Result<(usize, String), Box<dyn Error>> {
    let rel = bytes
        .get(offset..)
        .ok_or("cab string offset out of range")?
        .iter()
        .position(|&b| b == 0)
        .ok_or("cab string missing terminator")?;
    let end = offset + rel;
    let name = String::from_utf8_lossy(&bytes[offset..end]).to_string();
    Ok((end + 1, name))
}

fn decompress_cab_folder(
    bytes: &[u8],
    folder: &CabFolder,
    cb_cfdata: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut offset = folder.coff_cab_start as usize;
    let mut out = Vec::new();
    for _ in 0..folder.c_cfdata {
        if offset + 8 > bytes.len() {
            return Err("cab data block truncated".into());
        }
        let _checksum = read_u32_le_at(bytes, offset);
        offset += 4;
        let cb_data = read_u16_le_at(bytes, offset) as usize;
        offset += 2;
        let cb_uncomp = read_u16_le_at(bytes, offset) as usize;
        offset += 2;
        offset = offset.saturating_add(cb_cfdata);
        if offset + cb_data > bytes.len() {
            return Err("cab data block payload truncated".into());
        }
        let data = &bytes[offset..offset + cb_data];
        offset += cb_data;
        let chunk = decompress_cab_block(data, cb_uncomp, folder.type_compress)?;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn decompress_cab_block(
    data: &[u8],
    uncompressed_size: usize,
    type_compress: u16,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match type_compress & 0x000f {
        0 => {
            if data.len() < uncompressed_size {
                return Err("cab uncompressed block too small".into());
            }
            Ok(data[..uncompressed_size].to_vec())
        }
        1 => decompress_ms_zip_block(data),
        3 => Ok(wim_lzx::decompress(data, uncompressed_size)
            .map_err(|err| format!("cab LZX decode failed: {err}"))?),
        other => Err(format!("unsupported cab compression type {other}").into()),
    }
}

fn decompress_ms_zip_block(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if data.len() < 2 || data[0] != b'C' || data[1] != b'K' {
        return Err("cab MSZIP block missing CK signature".into());
    }

    let mut decoder = DeflateDecoder::new(Cursor::new(&data[2..]));
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn read_u16_le_at(bytes: &[u8], offset: usize) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(buf)
}

fn read_u32_le_at(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

struct ProgressUi {
    enabled: bool,
}

impl ProgressUi {
    fn new() -> Self {
        Self {
            enabled: std::io::stderr().is_terminal() || std::io::stdout().is_terminal(),
        }
    }

    async fn spinner<F, T>(&self, message: &str, future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        if !self.enabled {
            eprintln!("info: {message}");
            return future.await;
        }

        let bar = ProgressBar::new_spinner();
        bar.set_style(
            ProgressStyle::with_template("{spinner:.green} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        bar.set_message(message.to_owned());
        bar.enable_steady_tick(std::time::Duration::from_millis(80));
        let out = future.await;
        bar.finish_and_clear();
        out
    }

    async fn download(
        &self,
        client: &reqwest::Client,
        url: &str,
        output: &Path,
        total_size: u64,
        name: &str,
    ) -> Result<(), Box<dyn Error>> {
        if !self.enabled {
            return download_file(client, url, output).await;
        }

        let response = client.get(url).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("download failed with status {status} for {url}").into());
        }

        let bar = ProgressBar::new(total_size.max(1));
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        bar.set_message(format!("downloading {name}"));

        let mut file = tokio::fs::File::create(output).await?;
        let mut stream = response.bytes_stream();
        while let Some(item) = futures_util::StreamExt::next(&mut stream).await {
            let chunk = item?;
            bar.inc(chunk.len() as u64);
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        bar.finish_and_clear();
        Ok(())
    }
}

async fn post_soap(
    client: &reqwest::Client,
    url: &str,
    body: &str,
) -> Result<String, Box<dyn Error>> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(WU_USER_AGENT));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/soap+xml; charset=utf-8"),
    );

    let response = client
        .post(url)
        .headers(headers)
        .body(body.to_owned())
        .send()
        .await?;

    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return Err(format!("WU request failed with status {status}: {text}").into());
    }

    Ok(text)
}

async fn post_soap_with_retry(
    client: &reqwest::Client,
    url: &str,
    body: &str,
) -> Result<String, Box<dyn Error>> {
    for attempt in 0..3 {
        match post_soap(client, url, body).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                let retryable = error
                    .as_ref()
                    .downcast_ref::<reqwest::Error>()
                    .map(|reqwest_error| reqwest_error.is_connect() || reqwest_error.is_timeout())
                    .unwrap_or(false);
                if retryable && attempt < 2 {
                    sleep(Duration::from_millis(500 * (attempt + 1) as u64)).await;
                    continue;
                }
                return Err(error);
            }
        }
    }

    Err("request failed after retries".into())
}

async fn download_file(
    client: &reqwest::Client,
    url: &str,
    output: &Path,
) -> Result<(), Box<dyn Error>> {
    let response = client.get(url).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("download failed with status {status} for {url}").into());
    }

    let mut file = tokio::fs::File::create(output).await?;
    let mut stream = response.bytes_stream();
    while let Some(item) = futures_util::StreamExt::next(&mut stream).await {
        let chunk = item?;
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    Ok(())
}

fn select_update(
    sync_xml: &str,
    forced_update_id: Option<&str>,
    forced_revision: Option<u32>,
    arch: &str,
) -> Result<ChosenUpdate, Box<dyn Error>> {
    let update_infos = find_all_tag_blocks(sync_xml, "UpdateInfo");
    if update_infos.is_empty() {
        return Err("SyncUpdates response contained no UpdateInfo blocks".into());
    }

    let debug = std::env::var_os("UUP_DEBUG").is_some();
    if debug {
        eprintln!("debug: updateinfo blocks = {}", update_infos.len());
        eprintln!(
            "debug: sync contains <Files> = {}",
            sync_xml.contains("<Files>")
        );
    }

    let leaf_updates: Vec<String> = update_infos
        .iter()
        .filter(|info| is_leaf_update_info(info.as_str()))
        .cloned()
        .collect();
    if debug {
        eprintln!("debug: leaf updateinfo blocks = {}", leaf_updates.len());
    }

    let mut best = choose_update_candidate(
        &leaf_updates,
        sync_xml,
        forced_update_id,
        forced_revision,
        arch,
    );

    if let Some(candidate) = choose_update_candidate(
        &update_infos,
        sync_xml,
        forced_update_id,
        forced_revision,
        arch,
    ) {
        if best.as_ref().map_or(true, |current| {
            candidate_quality(&candidate) > candidate_quality(current)
        }) {
            best = Some(candidate);
        }
    }

    if let Some(candidate) =
        choose_update_from_update_blocks(sync_xml, forced_update_id, forced_revision, arch)
    {
        if best.as_ref().map_or(true, |current| {
            candidate_quality(&candidate) > candidate_quality(current)
        }) {
            best = Some(candidate);
        }
    }

    best.ok_or("no matching update found".into())
}

fn choose_update_candidate(
    infos: &[String],
    sync_xml: &str,
    forced_update_id: Option<&str>,
    forced_revision: Option<u32>,
    arch: &str,
) -> Option<ChosenUpdate> {
    let mut best_candidate = None;
    let debug = std::env::var_os("UUP_DEBUG").is_some();

    for info in infos {
        let Some(update_id) = extract_attr(info.as_str(), "UpdateID") else {
            continue;
        };
        if let Some(forced) = forced_update_id {
            if !update_id.eq_ignore_ascii_case(forced) {
                continue;
            }
        }

        let revision = extract_attr(info.as_str(), "RevisionNumber")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1);

        let numeric_id = extract_tag_text(info.as_str(), "ID")?;
        let mut files = extract_update_files(sync_xml, numeric_id.as_str());
        if files.is_empty() {
            if let Some(files_blob) = extract_tag_text(info.as_str(), "Files") {
                files = parse_update_files(files_blob.as_str());
            }
        }
        if files.is_empty() {
            continue;
        }

        let has_wim_esd = has_wim_or_esd_files(&files);
        let has_install = has_install_image_files(&files);
        let arch_match = info
            .to_ascii_lowercase()
            .contains(arch.to_ascii_lowercase().as_str());
        let score = if forced_update_id.is_some() {
            6
        } else if has_install {
            5
        } else if has_wim_esd {
            4
        } else if arch_match {
            2
        } else {
            1
        };

        if debug {
            eprintln!(
                "debug: candidate update_id={} rev={} files={} has_wim_esd={} has_install={} score={}",
                update_id,
                revision,
                files.len(),
                has_wim_esd,
                has_install,
                score
            );
        }

        let current = ChosenUpdate {
            update_id,
            revision: forced_revision.unwrap_or(revision),
            files,
        };

        if best_candidate
            .as_ref()
            .map_or(true, |(best_score, _)| score > *best_score)
        {
            best_candidate = Some((score, current));
        }

        if forced_update_id.is_some() {
            break;
        }
    }

    best_candidate.map(|(_, candidate)| candidate)
}

fn choose_update_from_update_blocks(
    sync_xml: &str,
    forced_update_id: Option<&str>,
    forced_revision: Option<u32>,
    arch: &str,
) -> Option<ChosenUpdate> {
    let update_blocks = find_all_tag_blocks(sync_xml, "Update");
    let mut best_candidate = None;
    let debug = std::env::var_os("UUP_DEBUG").is_some();

    for update_block in update_blocks {
        if !update_block.contains("<Files>") {
            continue;
        }

        let Some(update_id) = extract_attr(update_block.as_str(), "UpdateID") else {
            continue;
        };
        if let Some(forced) = forced_update_id {
            if !update_id.eq_ignore_ascii_case(forced) {
                continue;
            }
        }

        let revision = extract_attr(update_block.as_str(), "RevisionNumber")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1);

        let files_blob = extract_tag_text(update_block.as_str(), "Files")?;
        let mut files = parse_update_files(files_blob.as_str());
        if files.is_empty() {
            for nested_update in find_all_tag_blocks(update_block.as_str(), "Update") {
                if let Some(nested_files_blob) = extract_tag_text(nested_update.as_str(), "Files") {
                    files = parse_update_files(nested_files_blob.as_str());
                    if !files.is_empty() {
                        break;
                    }
                }
            }
        }
        if files.is_empty() {
            continue;
        }

        let has_wim_esd = has_wim_or_esd_files(&files);
        let has_install = has_install_image_files(&files);
        let arch_match = update_block
            .to_ascii_lowercase()
            .contains(arch.to_ascii_lowercase().as_str());
        let score = if forced_update_id.is_some() {
            6
        } else if has_install {
            5
        } else if has_wim_esd {
            4
        } else if arch_match {
            2
        } else {
            1
        };

        if debug {
            eprintln!(
                "debug: update-block candidate update_id={} rev={} files={} has_wim_esd={} has_install={} score={}",
                update_id,
                revision,
                files.len(),
                has_wim_esd,
                has_install,
                score
            );
        }

        let current = ChosenUpdate {
            update_id,
            revision: forced_revision.unwrap_or(revision),
            files,
        };

        if best_candidate
            .as_ref()
            .map_or(true, |(best_score, _)| score > *best_score)
        {
            best_candidate = Some((score, current));
        }

        if forced_update_id.is_some() {
            break;
        }
    }

    best_candidate.map(|(_, candidate)| candidate)
}

fn is_leaf_update_info(update_info: &str) -> bool {
    extract_tag_text(update_info, "IsLeaf")
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn extract_update_files(sync_xml: &str, numeric_id: &str) -> HashMap<String, UpdateFileInfo> {
    let debug = std::env::var_os("UUP_DEBUG").is_some();
    let update_blocks = find_all_tag_blocks(sync_xml, "Update");
    for update_block in update_blocks {
        if !update_block.contains(format!("<ID>{numeric_id}</ID>").as_str()) {
            continue;
        }
        let Some(files_blob) = extract_tag_text(update_block.as_str(), "Files") else {
            continue;
        };
        if debug {
            let file_tag_count = files_blob.matches("<File").count();
            let preview = files_blob.chars().take(260).collect::<String>();
            eprintln!(
                "debug: matched update numeric_id={} file_tags={} files_blob_preview={}",
                numeric_id,
                file_tag_count,
                preview.replace('\n', " ")
            );
        }
        return parse_update_files(files_blob.as_str());
    }
    HashMap::new()
}

fn parse_update_files(files_blob: &str) -> HashMap<String, UpdateFileInfo> {
    let mut files = HashMap::new();
    let mut cursor = 0usize;

    while let Some(start_rel) = files_blob[cursor..].find("<File") {
        let start = cursor + start_rel;
        let next_char = files_blob[start + "<File".len()..].chars().next();
        if matches!(next_char, Some(c) if c.is_alphabetic()) {
            cursor = start + "<File".len();
            continue;
        }

        let Some(tag_end_rel) = files_blob[start..].find('>') else {
            break;
        };
        let file_tag = &files_blob[start..start + tag_end_rel + 1];
        cursor = start + tag_end_rel + 1;

        let Some(digest_b64) = extract_attr(file_tag, "Digest") else {
            continue;
        };
        let Some(file_name) = extract_attr(file_tag, "FileName") else {
            continue;
        };
        let size = extract_attr(file_tag, "Size")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let Ok(digest) = STANDARD.decode(digest_b64.as_str()) else {
            continue;
        };

        files.insert(
            bytes_to_hex(&digest),
            UpdateFileInfo {
                name: file_name,
                size,
            },
        );
    }

    files
}

fn parse_file_locations(xml: &str) -> Result<Vec<DownloadLocation>, Box<dyn Error>> {
    let mut locations = Vec::new();
    for block in find_all_tag_blocks(xml, "FileLocation") {
        let Some(digest_b64) = extract_tag_text(block.as_str(), "FileDigest") else {
            continue;
        };
        let Some(url) = extract_tag_text(block.as_str(), "Url") else {
            continue;
        };

        locations.push(DownloadLocation {
            sha1_hex: bytes_to_hex(&STANDARD.decode(digest_b64.as_str())?),
            url: xml_unescape(url.as_str()),
        });
    }

    if locations.is_empty() {
        return Err("GetExtendedUpdateInfo2 returned no FileLocation entries".into());
    }

    Ok(locations)
}

fn pick_install_image(candidates: &[DownloadCandidate]) -> Option<&DownloadCandidate> {
    fn score(name: &str) -> u8 {
        if name.contains("install.wim") {
            4
        } else if name.contains("install.esd") {
            3
        } else if name.contains("install") {
            2
        } else {
            1
        }
    }

    candidates.iter().max_by(|a, b| {
        let a_name = a.name.to_ascii_lowercase();
        let b_name = b.name.to_ascii_lowercase();
        score(a_name.as_str())
            .cmp(&score(b_name.as_str()))
            .then(a.size.cmp(&b.size))
    })
}

fn has_wim_or_esd_files(files: &HashMap<String, UpdateFileInfo>) -> bool {
    files.values().any(|entry| {
        let name = entry.name.to_ascii_lowercase();
        name.ends_with(".wim")
            || name.ends_with(".esd")
            || name.contains(".wim")
            || name.contains(".esd")
    })
}

fn has_install_image_files(files: &HashMap<String, UpdateFileInfo>) -> bool {
    files.values().any(|entry| {
        let name = entry.name.to_ascii_lowercase();
        (name.contains("install") && name.contains(".wim"))
            || (name.contains("install") && name.contains(".esd"))
    })
}

fn candidate_quality(candidate: &ChosenUpdate) -> (u8, usize) {
    let install = has_install_image_files(&candidate.files);
    let wim_esd = has_wim_or_esd_files(&candidate.files);
    let class = if install {
        2
    } else if wim_esd {
        1
    } else {
        0
    };
    (class, candidate.files.len())
}

fn compose_get_cookie_request() -> String {
    let uuid = random_uuid_like();
    let now = unix_time();
    let created = w3c_time(now);
    let expires = w3c_time(now + 120);
    let device = uup_device();

    format!(
        "<s:Envelope xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
<s:Header>\
<a:Action s:mustUnderstand=\"1\">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie</a:Action>\
<a:MessageID>urn:uuid:{uuid}</a:MessageID>\
<a:To s:mustUnderstand=\"1\">{WU_CLIENT_ENDPOINT}</a:To>\
<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">\
<Timestamp xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><Created>{created}</Created><Expires>{expires}</Expires></Timestamp>\
<wuws:WindowsUpdateTicketsToken wsu:id=\"ClientMSA\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wuws=\"http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization\">\
<TicketType Name=\"MSA\" Version=\"1.0\" Policy=\"MBI_SSL\"><Device>{device}</Device></TicketType>\
</wuws:WindowsUpdateTicketsToken>\
</o:Security>\
</s:Header>\
<s:Body><GetCookie xmlns=\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService\"><oldCookie><Expiration>{created}</Expiration></oldCookie><lastChange>{created}</lastChange><currentTime>{created}</currentTime><protocolVersion>2.0</protocolVersion></GetCookie></s:Body>\
</s:Envelope>"
    )
}

fn compose_fetch_update_request(
    arch: &str,
    flight: &str,
    ring: &str,
    build: &str,
    sku: u32,
    release_type: &str,
    branch: &str,
    encrypted_data: &str,
) -> String {
    let uuid = random_uuid_like();
    let now = unix_time();
    let created = w3c_time(now);
    let expires = w3c_time(now + 120);
    let cookie_expires = w3c_time(now + 604_800);
    let device = uup_device();

    let branch = if branch == "auto" {
        branch_from_build(build)
    } else {
        branch.to_owned()
    };

    let main_product = if args_sku_is_server(sku) {
        "Server.OS"
    } else if sku == 180 {
        "WCOSDevice2.OS"
    } else if sku == 184 {
        "WCOSDevice1.OS"
    } else if sku == 189 {
        "WCOSDevice0.OS"
    } else if sku == 210 {
        "WNC.OS"
    } else {
        "Client.OS.rs2"
    };

    let mut products = Vec::new();
    for curr_arch in split_arches(arch) {
        products.push(format!(
            "PN={main_product}.{curr_arch}&Branch={branch}&PrimaryOSProduct=1&Repairable=1&V={build}&ReofferUpdate=1"
        ));
        products.push(format!("PN=Adobe.Flash.{curr_arch}&Repairable=1&V=0.0.0.0"));
        products.push(format!(
            "PN=Microsoft.Edge.Stable.{curr_arch}&Repairable=1&V=0.0.0.0"
        ));
        products.push(format!("PN=Microsoft.NETFX.{curr_arch}&V=0.0.0.0"));
        products.push(format!(
            "PN=Windows.Autopilot.{curr_arch}&Repairable=1&V=0.0.0.0"
        ));
        products.push(format!(
            "PN=Windows.AutopilotOOBE.{curr_arch}&Repairable=1&V=0.0.0.0"
        ));
        products.push(format!(
            "PN=Windows.Appraiser.{curr_arch}&Repairable=1&V={build}"
        ));
        products.push(format!(
            "PN=Windows.AppraiserData.{curr_arch}&Repairable=1&V={build}"
        ));
        products.push(format!("PN=Windows.EmergencyUpdate.{curr_arch}&V={build}"));
        products.push(format!(
            "PN=Windows.FeatureExperiencePack.{curr_arch}&Repairable=1&V=0.0.0.0"
        ));
        products.push(format!(
            "PN=Windows.ManagementOOBE.{curr_arch}&IsWindowsManagementOOBE=1&Repairable=1&V={build}"
        ));
        products.push(format!(
            "PN=Windows.OOBE.{curr_arch}&IsWindowsOOBE=1&Repairable=1&V={build}"
        ));
        products.push(format!("PN=Windows.UpdateStackPackage.{curr_arch}&Name=Update Stack Package&Repairable=1&V={build}"));
        products.push(format!(
            "PN=Hammer.{curr_arch}&Source=UpdateOrchestrator&V=0.0.0.0"
        ));
        products.push(format!(
            "PN=MSRT.{curr_arch}&Source=UpdateOrchestrator&V=0.0.0.0"
        ));
        products.push(format!(
            "PN=SedimentPack.{curr_arch}&Source=UpdateOrchestrator&V=0.0.0.0"
        ));
        products.push(format!(
            "PN=UUS.{curr_arch}&Source=UpdateOrchestrator&V=0.0.0.0"
        ));
    }

    let installed_ids_xml = INSTALLED_NON_LEAF_IDS
        .iter()
        .map(|id| format!("<int>{id}</int>"))
        .collect::<String>();

    let caller_attrib = xml_escape(
        "E:Profile=AUv2&Acquisition=1&Interactive=1&IsSeeker=1&SheddingAware=1&Id=MoUpdateOrchestrator",
    );
    let products = xml_escape(products.join(";").as_str());
    let device_attributes = compose_device_attributes(
        flight,
        ring,
        build,
        arch,
        sku,
        release_type,
        branch.as_str(),
    );

    format!(
        "<s:Envelope xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
<s:Header>\
<a:Action s:mustUnderstand=\"1\">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates</a:Action>\
<a:MessageID>urn:uuid:{uuid}</a:MessageID>\
<a:To s:mustUnderstand=\"1\">{WU_CLIENT_ENDPOINT}</a:To>\
<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">\
<Timestamp xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><Created>{created}</Created><Expires>{expires}</Expires></Timestamp>\
<wuws:WindowsUpdateTicketsToken wsu:id=\"ClientMSA\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wuws=\"http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization\">\
<TicketType Name=\"MSA\" Version=\"1.0\" Policy=\"MBI_SSL\"><Device>{device}</Device></TicketType>\
</wuws:WindowsUpdateTicketsToken>\
</o:Security>\
</s:Header>\
<s:Body><SyncUpdates xmlns=\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService\">\
<cookie><Expiration>{cookie_expires}</Expiration><EncryptedData>{encrypted_data}</EncryptedData></cookie>\
<parameters><ExpressQuery>false</ExpressQuery><InstalledNonLeafUpdateIDs>{installed_ids_xml}</InstalledNonLeafUpdateIDs><OtherCachedUpdateIDs/><SkipSoftwareSync>false</SkipSoftwareSync><NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates><AlsoPerformRegularSync>true</AlsoPerformRegularSync><ComputerSpec/><ExtendedUpdateInfoParameters><XmlUpdateFragmentTypes><XmlUpdateFragmentType>Extended</XmlUpdateFragmentType><XmlUpdateFragmentType>LocalizedProperties</XmlUpdateFragmentType></XmlUpdateFragmentTypes><Locales><string>en-US</string></Locales></ExtendedUpdateInfoParameters><ClientPreferredLanguages/><ProductsParameters><SyncCurrentVersionOnly>false</SyncCurrentVersionOnly><DeviceAttributes>{device_attributes}</DeviceAttributes><CallerAttributes>{caller_attrib}</CallerAttributes><Products>{products}</Products></ProductsParameters></parameters>\
</SyncUpdates></s:Body>\
</s:Envelope>"
    )
}

fn compose_file_get_request(
    update_id: &str,
    revision: u32,
    flight: &str,
    ring: &str,
    check_build: &str,
    arch: &str,
    sku: u32,
    release_type: &str,
    branch: &str,
) -> String {
    let uuid = random_uuid_like();
    let now = unix_time();
    let created = w3c_time(now);
    let expires = w3c_time(now + 120);
    let device = uup_device();

    let branch = if branch == "auto" {
        branch_from_build(check_build)
    } else {
        branch.to_owned()
    };

    let device_attributes = compose_device_attributes(
        flight,
        ring,
        check_build,
        arch,
        sku,
        release_type,
        branch.as_str(),
    );

    format!(
        "<s:Envelope xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\
<s:Header>\
<a:Action s:mustUnderstand=\"1\">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo2</a:Action>\
<a:MessageID>urn:uuid:{uuid}</a:MessageID>\
<a:To s:mustUnderstand=\"1\">{WU_CLIENT_SECURED_ENDPOINT}</a:To>\
<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">\
<Timestamp xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><Created>{created}</Created><Expires>{expires}</Expires></Timestamp>\
<wuws:WindowsUpdateTicketsToken wsu:id=\"ClientMSA\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wuws=\"http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization\">\
<TicketType Name=\"MSA\" Version=\"1.0\" Policy=\"MBI_SSL\"><Device>{device}</Device></TicketType>\
</wuws:WindowsUpdateTicketsToken>\
</o:Security>\
</s:Header>\
<s:Body><GetExtendedUpdateInfo2 xmlns=\"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService\"><updateIDs><UpdateIdentity><UpdateID>{update_id}</UpdateID><RevisionNumber>{revision}</RevisionNumber></UpdateIdentity></updateIDs><infoTypes><XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType><XmlUpdateFragmentType>FileDecryption</XmlUpdateFragmentType><XmlUpdateFragmentType>EsrpDecryptionInformation</XmlUpdateFragmentType><XmlUpdateFragmentType>PiecesHashUrl</XmlUpdateFragmentType><XmlUpdateFragmentType>BlockMapUrl</XmlUpdateFragmentType></infoTypes><deviceAttributes>{device_attributes}</deviceAttributes></GetExtendedUpdateInfo2></s:Body>\
</s:Envelope>"
    )
}

fn compose_device_attributes(
    _flight: &str,
    ring: &str,
    build: &str,
    arch: &str,
    sku: u32,
    release_type: &str,
    branch: &str,
) -> String {
    let branch = if branch == "auto" {
        branch_from_build(build)
    } else {
        branch.to_owned()
    };

    let mut block_upgrades = 0;
    let mut flight_enabled = 1;
    let mut is_retail = 0;

    if sku == 125 || sku == 126 {
        block_upgrades = 1;
    }

    let mut device_family = "Windows.Desktop".to_string();
    let mut installation_type = "Client".to_string();
    let mut product_type = "WinNT".to_string();

    if sku == 119 {
        device_family = "Windows.Team".to_string();
    }
    if args_sku_is_server(sku) {
        device_family = "Windows.Server".to_string();
        installation_type = "Server".to_string();
        product_type = "ServerNT".to_string();
        block_upgrades = 1;
    }
    if sku == 180 || sku == 184 || sku == 189 {
        device_family = "Windows.Core".to_string();
        installation_type = "FactoryOS".to_string();
    }

    let mut ring = ring.to_ascii_uppercase();
    let mut flt_branch = String::new();
    let mut flt_ring = "External".to_string();

    if ring == "RETAIL" {
        flt_ring = "Retail".to_string();
        flight_enabled = 0;
        is_retail = 1;
    }
    if ring == "WIF" {
        flt_branch = "Dev".to_string();
    }
    if ring == "WIS" {
        flt_branch = "Beta".to_string();
    }
    if ring == "RP" {
        flt_branch = "ReleasePreview".to_string();
    }
    if ring == "DEV" {
        flt_branch = "Dev".to_string();
        ring = "WIF".to_string();
    }
    if ring == "BETA" {
        flt_branch = "Beta".to_string();
        ring = "WIS".to_string();
    }
    if ring == "RELEASEPREVIEW" {
        flt_branch = "ReleasePreview".to_string();
        ring = "RP".to_string();
    }
    if ring == "MSIT" {
        flt_branch = "MSIT".to_string();
        flt_ring = "Internal".to_string();
    }
    if ring == "CANARY" {
        flt_branch = "CanaryChannel".to_string();
        ring = "WIF".to_string();
    }

    let build_num = build
        .split('.')
        .nth(2)
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);

    if build_num < 17_763 {
        if ring == "RP" {
            // Legacy pre-RS5 behavior in the PHP implementation.
        }
        flt_branch = "external".to_string();
        flt_ring = ring.clone();
    }

    let now = unix_time();
    let expires = now + 82_800;
    let timestamp = now.saturating_sub(3_600);

    let attrs = [
        format!("App=WU_OS"),
        format!("AppVer={build}"),
        format!("AttrDataVer=331"),
        format!("AllowInPlaceUpgrade=1"),
        format!("AllowOptionalContent=1"),
        format!("AllowUpgradesWithUnsupportedTPMOrCPU=1"),
        format!("BlockFeatureUpdates={block_upgrades}"),
        format!("BranchReadinessLevel=CB"),
        format!("CIOptin=1"),
        format!("CurrentBranch={branch}"),
        format!("DataExpDateEpoch_GE25H2={expires}"),
        format!("DataExpDateEpoch_GE24H2={expires}"),
        format!("DataExpDateEpoch_GE24H2Setup={expires}"),
        format!("DataExpDateEpoch_CU23H2={expires}"),
        format!("DataExpDateEpoch_CU23H2Setup={expires}"),
        format!("DataExpDateEpoch_NI22H2={expires}"),
        format!("DataExpDateEpoch_NI22H2Setup={expires}"),
        format!("DataExpDateEpoch_CO21H2={expires}"),
        format!("DataExpDateEpoch_CO21H2Setup={expires}"),
        format!("DataExpDateEpoch_23H2={expires}"),
        format!("DataExpDateEpoch_22H2={expires}"),
        format!("DataExpDateEpoch_21H2={expires}"),
        format!("DataExpDateEpoch_21H1={expires}"),
        format!("DataExpDateEpoch_20H1={expires}"),
        format!("DataExpDateEpoch_19H1={expires}"),
        format!("DataVer_RS5=2000000000"),
        format!("DefaultUserRegion=191"),
        format!("DeviceFamily={device_family}"),
        format!("DeviceInfoGatherSuccessful=1"),
        format!("EKB19H2InstallCount=1"),
        format!("EKB19H2InstallTimeEpoch=1255000000"),
        format!("FlightingBranchName={flt_branch}"),
        format!("FlightRing={flt_ring}"),
        format!("Free=gt64"),
        format!("GStatus_GE25H2=2"),
        format!("GStatus_GE24H2=2"),
        format!("GStatus_GE24H2Setup=2"),
        format!("GStatus_CU23H2=2"),
        format!("GStatus_CU23H2Setup=2"),
        format!("GStatus_NI23H2=2"),
        format!("GStatus_NI22H2=2"),
        format!("GStatus_NI22H2Setup=2"),
        format!("GStatus_CO21H2=2"),
        format!("GStatus_CO21H2Setup=2"),
        format!("GStatus_22H2=2"),
        format!("GStatus_21H2=2"),
        format!("GStatus_21H1=2"),
        format!("GStatus_20H1=2"),
        format!("GStatus_20H1Setup=2"),
        format!("GStatus_19H1=2"),
        format!("GStatus_19H1Setup=2"),
        format!("GStatus_RS5=2"),
        format!("GenTelRunTimestamp_19H1={timestamp}"),
        format!("InstallDate=1438196400"),
        format!("InstallLanguage=en-US"),
        format!("InstallationType={installation_type}"),
        format!("IsDeviceRetailDemo=0"),
        format!("IsFlightingEnabled={flight_enabled}"),
        format!("IsRetailOS={is_retail}"),
        format!("LCUVer=0.0.0.0"),
        format!("MediaBranch="),
        format!("MediaVersion={build}"),
        format!("CloudPBR=1"),
        format!("DUScan=1"),
        format!("OEMModel=21F6CTO1WW"),
        format!("OEMModelBaseBoard=21F6CTO1WW"),
        format!("OEMName_Uncleaned=LENOVO"),
        format!("OemPartnerRing=UPSFlighting"),
        format!("OSArchitecture={arch}"),
        format!("OSSkuId={sku}"),
        format!("OSUILocale=en-US"),
        format!("OSVersion={build}"),
        format!("ProcessorIdentifier=Intel64 Family 6 Model 186 Stepping 3"),
        format!("ProcessorManufacturer=GenuineIntel"),
        format!("ProcessorModel=13th Gen Intel(R) Core(TM) i7-1355U"),
        format!("ProductType={product_type}"),
        format!("ReleaseType={release_type}"),
        format!("SdbVer_20H1=2000000000"),
        format!("SdbVer_19H1=2000000000"),
        format!("SecureBootCapable=1"),
        format!("TelemetryLevel=3"),
        format!("TimestampEpochString_GE24H2={timestamp}"),
        format!("TimestampEpochString_GE24H2Setup={timestamp}"),
        format!("TimestampEpochString_CU23H2={timestamp}"),
        format!("TimestampEpochString_CU23H2Setup={timestamp}"),
        format!("TimestampEpochString_NI23H2={timestamp}"),
        format!("TimestampEpochString_NI22H2={timestamp}"),
        format!("TimestampEpochString_NI22H2Setup={timestamp}"),
        format!("TimestampEpochString_CO21H2={timestamp}"),
        format!("TimestampEpochString_CO21H2Setup={timestamp}"),
        format!("TimestampEpochString_22H2={timestamp}"),
        format!("TimestampEpochString_21H2={timestamp}"),
        format!("TimestampEpochString_21H1={timestamp}"),
        format!("TimestampEpochString_20H1={timestamp}"),
        format!("TimestampEpochString_19H1={timestamp}"),
        format!("TPMVersion=2"),
        format!("UpdateManagementGroup=2"),
        format!("UpdateOfferedDays=0"),
        format!("UpgEx_GE25H2=Green"),
        format!("UpgEx_GE24H2Setup=Green"),
        format!("UpgEx_GE24H2=Green"),
        format!("UpgEx_CU23H2=Green"),
        format!("UpgEx_NI23H2=Green"),
        format!("UpgEx_NI22H2=Green"),
        format!("UpgEx_CO21H2=Green"),
        format!("UpgEx_23H2=Green"),
        format!("UpgEx_22H2=Green"),
        format!("UpgEx_21H2=Green"),
        format!("UpgEx_21H1=Green"),
        format!("UpgEx_20H1=Green"),
        format!("UpgEx_19H1=Green"),
        format!("UpgEx_RS5=Green"),
        format!("UpgradeAccepted=1"),
        format!("UpgradeEligible=1"),
        format!("UserInPlaceUpgrade=1"),
        format!("VBSState=2"),
        format!("Version_RS5=2000000000"),
        format!("Win10CommercialAzureESUEligible=1"),
        format!("Win10CommercialKeybasedESUEligible=1"),
        format!("Win10CommercialW365ESUEligible=1"),
        format!("Win10ConsumerESUStatus=3"),
        format!("Win10ConsumerESUAY=9"),
        format!("WuClientVer={build}"),
    ];

    xml_escape(format!("E:{}", attrs.join("&")).as_str())
}

fn normalize_build(build: &str) -> Result<String, Box<dyn Error>> {
    let mut split = build.split('.');
    let major = split
        .next()
        .ok_or("build must be in MAJOR.MINOR format, e.g. 26100.1")?;
    let minor = split.next().unwrap_or("1");

    Ok(format!(
        "10.0.{}.{}",
        major.parse::<u32>()?,
        minor.parse::<u32>()?
    ))
}

fn split_arches(arch: &str) -> Vec<&str> {
    if arch.eq_ignore_ascii_case("all") {
        vec!["amd64", "x86", "arm64", "arm"]
    } else {
        vec![arch]
    }
}

fn args_sku_is_server(sku: u32) -> bool {
    matches!(
        sku,
        7 | 8 | 12 | 13 | 79 | 80 | 120 | 145 | 146 | 147 | 148 | 159 | 160 | 406 | 407 | 408
    )
}

fn branch_from_build(build: &str) -> String {
    let major = build
        .split('.')
        .nth(2)
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(26_100);

    match major {
        15_063 => "rs2_release".to_string(),
        16_299 => "rs3_release".to_string(),
        17_134 => "rs4_release".to_string(),
        17_763 => "rs5_release".to_string(),
        17_784 => "rs5_release_svc_hci".to_string(),
        18_362 | 18_363 => "19h1_release".to_string(),
        19_041..=19_046 => "vb_release".to_string(),
        20_279 => "fe_release_10x".to_string(),
        20_348 | 20_349 => "fe_release".to_string(),
        22_000 => "co_release".to_string(),
        22_621 | 22_631 | 22_635 => "ni_release".to_string(),
        25_398 => "zn_release".to_string(),
        26_100 | 26_120 | 26_200 => "ge_release".to_string(),
        28_000 => "br_release".to_string(),
        _ => "rs_prerelease".to_string(),
    }
}

fn find_all_tag_blocks(input: &str, tag: &str) -> Vec<String> {
    let start_tag = format!("<{tag}");
    let end_tag = format!("</{tag}>");
    let mut out = Vec::new();
    let mut cursor = 0usize;

    while let Some(start_rel) = input[cursor..].find(start_tag.as_str()) {
        let start = cursor + start_rel;
        let next_char = input[start + start_tag.len()..].chars().next();
        if matches!(next_char, Some(c) if c.is_alphabetic()) {
            cursor = start + start_tag.len();
            continue;
        }

        let Some(open_end_rel) = input[start..].find('>') else {
            break;
        };
        let content_start = start + open_end_rel + 1;
        let Some(end_rel) = input[content_start..].find(end_tag.as_str()) else {
            break;
        };

        let end = content_start + end_rel + end_tag.len();
        out.push(input[start..end].to_string());
        cursor = end;
    }

    out
}

fn extract_tag_text(input: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{tag}");
    let end_tag = format!("</{tag}>");
    let mut start = input.find(start_tag.as_str())?;

    while matches!(input[start + start_tag.len()..].chars().next(), Some(c) if c.is_alphabetic()) {
        let next_search_start = start + start_tag.len();
        start = input[next_search_start..].find(start_tag.as_str())? + next_search_start;
    }

    let open_end = input[start..].find('>')? + start;
    let content_start = open_end + 1;
    let end = input[content_start..].find(end_tag.as_str())? + content_start;
    Some(input[content_start..end].to_string())
}

fn extract_attr(input: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let start = input.find(needle.as_str())? + needle.len();
    let end = input[start..].find('"')? + start;
    Some(input[start..end].to_string())
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(hex_char((b >> 4) & 0x0f));
        s.push(hex_char(b & 0x0f));
    }
    s
}

fn hex_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

fn uup_device() -> String {
    let mut rng = XorShift64::seeded();
    let t_header = "13003002c377040014d5bcac7a66de0d50beddf9bba16c87edb9e019898000";
    let t_end = "b401";

    let mut random_hex = String::with_capacity(1054);
    for _ in 0..1054 {
        random_hex.push(hex_char((rng.next_u64() & 0x0f) as u8));
    }

    let t_value =
        hex_to_bytes(format!("{t_header}{random_hex}{t_end}").as_str()).unwrap_or_default();
    let t_b64 = STANDARD.encode(&t_value);
    let raw = format!("t={t_b64}&p=");

    let mut nul_separated = Vec::with_capacity(raw.len() * 2);
    for byte in raw.bytes() {
        nul_separated.push(byte);
        nul_separated.push(0);
    }

    STANDARD.encode(&nul_separated)
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn w3c_time(ts: i64) -> String {
    let secs = if ts < 0 { 0 } else { ts as u64 };
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    let (year, month, day) = civil_from_days(days as i64 + 719_468);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d)
}

fn random_uuid_like() -> String {
    let mut rng = XorShift64::seeded();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        rng.next_u32(),
        (rng.next_u32() & 0xffff),
        (rng.next_u32() & 0x0fff),
        ((rng.next_u32() & 0x3fff) | 0x8000),
        (rng.next_u64() & 0x000f_ffff_ffff_ffff)
    )
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }

    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn seeded() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678_9abc_def0);
        Self {
            state: nanos ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
}
