import os
import sys
import re
import json
import base64
import time
import socket
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

import requests
from tqdm import tqdm
from ping3 import ping
import geoip2.database

# ------------------- CONFIGURATION -------------------

INPUT_URLS_FILE = "Urls"
GEOIP_DB_PATH = "GeoLite2-City.mmdb"

ALLOWED_COUNTRIES = {"US", "GB", "DE", "FR", "FI", "IR"}
PING_MIN = 100
PING_MAX = 200
PING_TIMEOUT = 3  # seconds

# Output folders
OUTPUT_DIRS = {
    "downloaded": Path("OutputUrls"),
    "no_url": Path("configs_without_url"),
    "decoded": Path("decrypted_configs"),
    "valid": Path("valid_configs"),
    "invalid": Path("invalid_configs"),
    "separated": Path("separated_configs"),
}

for path in OUTPUT_DIRS.values():
    path.mkdir(parents=True, exist_ok=True)

# ------------------- UTILITY FUNCTIONS -------------------

def safe_write_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def is_base64(s: str) -> bool:
    # Remove whitespace and check base64 pattern
    s = s.strip().replace('\n', '').replace('\r', '')
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def extract_server_address(content: str):
    """
    Extracts the server address from vmess or vless config.
    Returns (protocol, address) or (None, None) if not valid.
    """
    if content.startswith("vmess://"):
        try:
            b64 = content[len("vmess://"):]
            padded_b64 = b64 + '=' * (-len(b64) % 4)
            decoded = base64.urlsafe_b64decode(padded_b64).decode("utf-8")
            data = json.loads(decoded)
            return "vmess", data.get("add")
        except Exception:
            return None, None
    elif content.startswith("vless://"):
        match = re.match(r"^vless://[^@]+@([^:]+):", content)
        if match:
            return "vless", match.group(1)
        else:
            return None, None
    else:
        return None, None

def get_country_info(ip_or_host, geoip_reader):
    try:
        ip = socket.gethostbyname(ip_or_host)
        response = geoip_reader.city(ip)
        return response.country.iso_code or "Unknown", response.country.name or "Unknown"
    except Exception:
        return "Unknown", "Unknown"

def get_ping(host):
    try:
        latency = ping(host, timeout=PING_TIMEOUT)
        if latency is not None:
            return round(latency * 1000, 2)  # ms
    except Exception:
        pass
    return None

# ------------------- PIPELINE STAGES -------------------

def download_urls(input_file: str, output_folder: Path, max_workers=10):
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            urls = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"❌ Error: Input file '{input_file}' not found.")
        sys.exit(1)

    results = []
    failed_urls = []

    def process_url(args):
        idx, url = args
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200 and response.text.strip():
                file_path = output_folder / f"{idx}.txt"
                safe_write_text(file_path, f"URL: {url}\n\n{response.text}")
                return (True, url)
            else:
                return (False, url)
        except Exception:
            return (False, url)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for success, url in tqdm(executor.map(process_url, enumerate(urls)), total=len(urls), desc="Downloading URLs"):
            if not success:
                failed_urls.append(url)

    print(f"✅ Successfully downloaded {len(urls) - len(failed_urls)} configurations.")
    print(f"❌ Failed to download {len(failed_urls)} configurations.")
    if failed_urls:
        print("🚫 Failed URLs:")
        for failed_url in failed_urls:
            print(f"   - {failed_url}")

def remove_url_headers(input_folder: Path, output_folder: Path):
    url_pattern = re.compile(r'^URL: https?://[^\s]+')
    files = list(input_folder.iterdir())
    failed_files = []

    for file_path in tqdm(files, desc="Removing URL headers", unit="file"):
        if file_path.is_file():
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    lines = file.readlines()
                if lines and url_pattern.match(lines[0].strip()):
                    lines = lines[1:]
                output_file_path = output_folder / file_path.name
                safe_write_text(output_file_path, "".join(lines))
            except Exception as e:
                failed_files.append(file_path.name)
                print(f"❌ Failed to process {file_path.name}: {e}")

    print(f"✅ Successfully processed {len(files) - len(failed_files)} files.")
    print(f"❌ Failed to process {len(failed_files)} files.")
    if failed_files:
        print("🚫 Failed files:")
        for failed_file in failed_files:
            print(f"   - {failed_file}")

def decode_base64_configs(input_folder: Path, output_folder: Path):
    base64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
    url_pattern = re.compile(r'^https?://[^\s]+')
    files = list(input_folder.iterdir())
    failed_files = []

    for file_path in tqdm(files, desc="Base64 decoding", unit="file"):
        if file_path.is_file():
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    content = file.read().strip()
                content_without_url = re.sub(url_pattern, "", content).strip()
                if is_base64(content_without_url):
                    try:
                        decoded_content = base64.b64decode(content_without_url).decode("utf-8")
                        safe_write_text(output_folder / file_path.name, decoded_content)
                    except Exception as e:
                        failed_files.append(file_path.name)
                        print(f"❌ Failed to decode {file_path.name}: {e}")
                else:
                    # Save as is
                    safe_write_text(output_folder / file_path.name, content)
            except Exception as e:
                failed_files.append(file_path.name)
                print(f"❌ Failed to read {file_path.name}: {e}")

    print(f"✅ Successfully processed {len(files) - len(failed_files)} files.")
    print(f"❌ Failed to decode {len(failed_files)} files.")
    if failed_files:
        print("🚫 Failed files:")
        for failed_file in failed_files:
            print(f"   - {failed_file}")

def validate_and_ping_configs(input_folder: Path, valid_folder: Path, invalid_folder: Path, geoip_db_path: str):
    files = list(input_folder.iterdir())
    geoip_reader = geoip2.database.Reader(geoip_db_path)
    valid_count = 0
    invalid_count = 0

    ping_futures = {}
    file_infos = {}

    with ThreadPoolExecutor(max_workers=32) as executor:
        for file_path in tqdm(files, desc="Extracting and filtering", unit="file"):
            if not file_path.is_file():
                continue
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    content = file.read().strip()
                content = re.sub(r'^https?://[^\s]+', "", content).strip()
                if content.startswith("#"):
                    content = "\n".join([line for line in content.split("\n") if not line.startswith("#")]).strip()
                protocol, server = extract_server_address(content)
                if protocol and server:
                    country_code, _ = get_country_info(server, geoip_reader)
                    if country_code and country_code.upper() in ALLOWED_COUNTRIES:
                        future = executor.submit(get_ping, server)
                        ping_futures[future] = (file_path, content, protocol, server, country_code)
                        file_infos[file_path.name] = (content, protocol, server, country_code)
                    else:
                        safe_write_text(invalid_folder / file_path.name, content)
                        invalid_count += 1
                        print(f"❌ {file_path.name} is from disallowed country ({country_code}).")
                else:
                    safe_write_text(invalid_folder / file_path.name, content)
                    invalid_count += 1
                    print(f"❌ {file_path.name} is invalid format.")
            except Exception as e:
                invalid_count += 1
                print(f"❌ Failed to process {file_path.name}: {e}")

        for future in tqdm(as_completed(ping_futures), total=len(ping_futures), desc="Pinging servers"):
            file_path, content, protocol, server, country_code = ping_futures[future]
            latency = future.result()
            if latency is not None and PING_MIN <= latency <= PING_MAX:
                safe_write_text(valid_folder / file_path.name, content)
                valid_count += 1
                print(f"✅ {file_path.name} is valid and saved. (Country: {country_code}, Ping: {latency:.1f}ms)")
            else:
                safe_write_text(invalid_folder / file_path.name, content)
                invalid_count += 1
                print(f"❌ {file_path.name} is invalid due to ping ({latency if latency is not None else 'unreachable'} ms).")

    geoip_reader.close()
    print(f"✅ Successfully validated {valid_count} files.")
    print(f"❌ {invalid_count} files are invalid.")

def combine_files_to_txt(folder_path: Path, output_txt_path: Path, folder_type: str):
    files = [f for f in folder_path.iterdir() if f.is_file()]
    files_processed = 0

    with open(output_txt_path, "w", encoding="utf-8") as output_file:
        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    content = file.read().strip()
                    output_file.write(content + "\n\n")
                file_path.unlink()
                files_processed += 1
                print(f"✅ {file_path.name} added to {output_txt_path} and deleted. Progress: {files_processed}/{len(files)}")
            except Exception as e:
                print(f"❌ Failed to read or delete {file_path.name}: {e}")

    print(f"\n📂 Operation Summary for {folder_type} files:")
    print(f"Total files in {folder_type} folder: {len(files)}")
    print(f"Successfully processed files: {files_processed}")
    print(f"Failed to process files: {len(files) - files_processed}")

def categorize_and_generate_html(input_file: Path, output_folder: Path, geoip_db_path: str):
    output_folder.mkdir(parents=True, exist_ok=True)
    with open(input_file, 'r', encoding='utf-8') as file:
        lines = [line.strip() for line in file if line.strip()]

    if not lines:
        print("[INFO] No configurations found in the input file.")
        return

    print(f"[INFO] Total configurations found: {len(lines)}")
    print("[INFO] Starting the categorization process...\n")

    geoip_reader = geoip2.database.Reader(geoip_db_path)

    valid_formats = {
        r"^vmess://": "vmess",
        r"^vless://": "vless"
    }

    valid_configs = []
    invalid_configs = []
    unrecognized_configs = []

    for index, line in enumerate(lines, start=1):
        categorized = False
        for pattern, fmt in valid_formats.items():
            if re.match(pattern, line):
                server = extract_server_address(line)[1]
                if not server:
                    invalid_configs.append((line, "Could not extract server"))
                    categorized = True
                    break
                country_code, country_name = get_country_info(server, geoip_reader)
                if country_code not in ALLOWED_COUNTRIES:
                    invalid_configs.append((line, f"Country not allowed: {country_code}"))
                    categorized = True
                    break
                ping_ms = get_ping(server)
                if ping_ms is None or not (PING_MIN <= ping_ms <= PING_MAX):
                    invalid_configs.append((line, f"Ping out of range or unreachable: {ping_ms}"))
                    categorized = True
                    break
                # Passed all checks
                valid_configs.append({
                    "line": line,
                    "format": fmt,
                    "country_code": country_code,
                    "country_name": country_name,
                    "ping": ping_ms,
                    "server": server
                })
                categorized = True
                break
        if not categorized:
            unrecognized_configs.append(line)

        if index % 100 == 0 or index == len(lines):
            print(f"[PROGRESS] Processed {index}/{len(lines)} configurations...")

    geoip_reader.close()

    # Write separated configs
    vmess_lines = [c["line"] for c in valid_configs if c["format"] == "vmess"]
    vless_lines = [c["line"] for c in valid_configs if c["format"] == "vless"]
    if vmess_lines:
        safe_write_text(output_folder / "vmess.txt", "\n".join(vmess_lines))
    if vless_lines:
        safe_write_text(output_folder / "vless.txt", "\n".join(vless_lines))
    if unrecognized_configs:
        safe_write_text(output_folder / "unknown_configs.txt", "\n".join(unrecognized_configs))
    if invalid_configs:
        with open(output_folder / "invalid_configs.txt", "w", encoding="utf-8") as f:
            for line, reason in invalid_configs:
                f.write(f"{line}    # {reason}\n")

    # Sort valid configs by country, then by ping
    valid_configs.sort(key=lambda x: (x["country_name"], x["ping"]))

    # Generate per-country HTML files
    def generate_country_htmls(valid_configs, output_folder: Path):
        """
        Generate one HTML file per country, listing only that country's valid configs.
        Adds a button to copy all config lines to clipboard.
        """
        country_groups = defaultdict(list)
        for c in valid_configs:
            country_groups[c["country_code"]].append(c)

        for country_code, configs in country_groups.items():
            country_name = configs[0]["country_name"] if configs else country_code
            html = [
                "<!DOCTYPE html>",
                "<html><head><meta charset='utf-8'><title>V2Ray Configs - {}</title>".format(country_name),
                "<style>",
                "body { font-family: Isabella, sans-serif; font-size: 20px; background: #e0cccc; color: #3C0707; }",
                "table { border-collapse: collapse; width: 100%; margin-bottom: 40px; }",
                "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }",
                "th { background: #6282B6; }",
                ".vmess { color: #1B3B6F; font-size: 15px; font-weight: bold;  }",
                ".vless { color: #6282B6; font-size: 15px; font-weight: bold;  }",
                ".copy-btn { background: #6282B6; color: white; border: none; padding: 10px 18px; border-radius: 5px; font-size: 18px; cursor: pointer; margin-bottom: 20px; }",
                ".copy-btn:active { background: #3C0707; }",
                ".copied-msg { color: green; font-size: 16px; margin-left: 10px; display: none; }",
                "</style></head><body>",
                f"<h1>V2Ray Configurations for {country_name} ({country_code})</h1>",
                '<button class="copy-btn" onclick="copyAllConfigs()">Copy All Configs</button><span class="copied-msg" id="copiedMsg">Copied!</span>',
                "<table>",
                "<tr><th>Format</th><th>Country</th><th>Ping (ms)</th><th>Server</th><th>Configuration</th></tr>"
            ]
            for c in configs:
                fmt_class = "vmess" if c["format"] == "vmess" else "vless"
                html.append(
                    f"<tr>"
                    f"<td class='{fmt_class}'>{c['format'].upper()}</td>"
                    f"<td>{c['country_name']} ({c['country_code']})</td>"
                    f"<td>{c['ping']:.2f}</td>"
                    f"<td>{c['server']}</td>"
                    f"<td><code>{c['line']}</code></td>"
                    f"</tr>"
                )
            html.append("</table>")
            # Add JavaScript for copy functionality
            html.append("""
    <script>
    function copyAllConfigs() {
        const codes = Array.from(document.querySelectorAll('table code')).map(el => el.textContent);
        const text = codes.join('\\n');
        navigator.clipboard.writeText(text).then(function() {
            var msg = document.getElementById('copiedMsg');
            msg.style.display = 'inline';
            setTimeout(() => { msg.style.display = 'none'; }, 1200);
        });
    }
    </script>
    """)
            html.append("</body></html>")
            html_filename = output_folder / f"{country_code}.html"
            safe_write_text(html_filename, "\n".join(html))
            print(f"[✅] HTML file generated for {country_name} ({country_code}): {html_filename}")

    print("\n================ FINAL REPORT ================")
    print(f"📂 Total Configurations Processed: {len(lines)}")
    print(f"✅ Valid & Categorized: {len(valid_configs)}")
    print(f"❌ Invalid (country/ping/extract): {len(invalid_configs)}")
    print(f"⚠️ Unrecognized Configs: {len(unrecognized_configs)}")
    print("=============================================")

def generate_country_htmls(valid_configs, output_folder: Path):
    """
    Generate one HTML file per country, listing only that country's valid configs.
    """
    country_groups = defaultdict(list)
    for c in valid_configs:
        country_groups[c["country_code"]].append(c)

    for country_code, configs in country_groups.items():
        country_name = configs[0]["country_name"] if configs else country_code
        html = [
            "<!DOCTYPE html>",
            "<html><head><meta charset='utf-8'><title>V2Ray Configs - {}</title>".format(country_name),
            "<style>",
            "body { font-family: Isabella, sans-serif; font-size: 20px; background: #e0cccc; color: #3C0707; }",
            "table { border-collapse: collapse; width: 100%; margin-bottom: 40px; }",
            "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }",
            "th { background: #6282B6; }",
            ".vmess { color: #1B3B6F; font-size: 15px; font-weight: bold;  }",
            ".vless { color: #6282B6; font-size: 15px; font-weight: bold;  }",
            "</style></head><body>",
            f"<h1>V2Ray Configurations for {country_name} ({country_code})</h1>",
            "<table>",
            "<tr><th>Format</th><th>Country</th><th>Ping (ms)</th><th>Server</th><th>Configuration</th></tr>"
        ]
        for c in configs:
            fmt_class = "vmess" if c["format"] == "vmess" else "vless"
            html.append(
                f"<tr>"
                f"<td class='{fmt_class}'>{c['format'].upper()}</td>"
                f"<td>{c['country_name']} ({c['country_code']})</td>"
                f"<td>{c['ping']:.2f}</td>"
                f"<td>{c['server']}</td>"
                f"<td><code>{c['line']}</code></td>"
                f"</tr>"
            )
        html.append("</table></body></html>")
        html_filename = output_folder / f"{country_code}.html"
        safe_write_text(html_filename, "\n".join(html))
        print(f"[✅] HTML file generated for {country_name} ({country_code}): {html_filename}")

# ------------------- MAIN PIPELINE -------------------

def main():
    t0 = time.time()
    print("\n=== [1] Downloading URLs ===")
    download_urls(INPUT_URLS_FILE, OUTPUT_DIRS["downloaded"])

    print("\n=== [2] Removing URL Headers ===")
    remove_url_headers(OUTPUT_DIRS["downloaded"], OUTPUT_DIRS["no_url"])

    print("\n=== [3] Base64 Decoding ===")
    decode_base64_configs(OUTPUT_DIRS["no_url"], OUTPUT_DIRS["decoded"])

    print("\n=== [4] Validating and Pinging Configs ===")
    validate_and_ping_configs(
        OUTPUT_DIRS["decoded"],
        OUTPUT_DIRS["valid"],
        OUTPUT_DIRS["invalid"],
        GEOIP_DB_PATH
    )

    print("\n=== [5] Combining Valid/Invalid Files ===")
    combine_files_to_txt(OUTPUT_DIRS["valid"], OUTPUT_DIRS["valid"] / "combined_valid.txt", "Valid")
    combine_files_to_txt(OUTPUT_DIRS["invalid"], OUTPUT_DIRS["invalid"] / "combined_invalid.txt", "Invalid")

    print("\n=== [6] Categorizing and Generating HTML ===")
    categorize_and_generate_html(
        OUTPUT_DIRS["valid"] / "combined_valid.txt",
        OUTPUT_DIRS["separated"],
        GEOIP_DB_PATH
    )

    print(f"\n⏳ Total Pipeline Time: {time.time() - t0:.2f} seconds")

if __name__ == "__main__":
    main()
