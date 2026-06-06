#!/usr/bin/env python3
"""
V2Ray Config Collector - نسخه نهایی و کامل
جمع‌آوری خودکار کانفیگ‌های V2Ray و پروکسی‌های MTProto (تلگرام) + تولید README پویا
"""

import json
import re
import base64
import html
import sys
import os
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Set, Dict
from urllib.parse import unquote, urlparse, parse_qs
from datetime import datetime

import requests
from bs4 import BeautifulSoup

# ============================================================================
# Logging Configuration
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

CONFIG = {
    'channels_file': os.getenv('CHANNELS_FILE', 'channels.json'),
    'sources_file': os.getenv('SOURCES_FILE', 'sources.json'),
    'output_dir': os.getenv('OUTPUT_DIR', '.'),
    'max_workers': int(os.getenv('MAX_WORKERS', '10')),
    'timeout': int(os.getenv('TIMEOUT', '20')),
    'max_retries': int(os.getenv('MAX_RETRIES', '3')),
    'telegram_base_url': 'https://t.me/s/',
    'lite_config_count': int(os.getenv('LITE_CONFIG_COUNT', '15')),
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'repo_owner': os.getenv('REPO_OWNER', 'Par123456'),
    'repo_name': os.getenv('REPO_NAME', 'auto-sub'),
    'branch': os.getenv('BRANCH', 'main')
}

SUPPORTED_PROTOCOLS = [
    'vmess', 'vless', 'trojan', 'ss', 'ssr', 'tuic',
    'socks', 'juicity', 'reality', 'hysteria', 'hysteria2',
    'ssh', 'wireguard', 'mtproto'
]

PROTOCOL_DISPLAY_NAMES = {
    'vmess': 'VMess', 'vless': 'VLess', 'trojan': 'Trojan',
    'ss': 'Shadowsocks', 'ssr': 'SSR', 'tuic': 'TUIC',
    'socks': 'Socks', 'juicity': 'Juicity', 'reality': 'Reality',
    'hysteria': 'Hysteria', 'hysteria2': 'Hysteria2',
    'ssh': 'SSH', 'wireguard': 'WireGuard', 'mtproto': 'MTProto (Telegram Proxy)'
}

PROTOCOL_PATTERNS = {
    'vmess': re.compile(r'vmess://[A-Za-z0-9+/=_-]+={0,2}'),
    'vless': re.compile(r'vless://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'trojan': re.compile(r'trojan://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'ss': re.compile(r'ss://[A-Za-z0-9+/=_-]+(?:@[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)?'),
    'ssr': re.compile(r'ssr://[A-Za-z0-9+/=_-]+'),
    'tuic': re.compile(r'tuic://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'socks': re.compile(r'socks://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'juicity': re.compile(r'juicity://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'reality': re.compile(r'reality://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'hysteria': re.compile(r'hysteria://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'hysteria2': re.compile(r'(?:hysteria2|hy2)://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'ssh': re.compile(r'ssh://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'wireguard': re.compile(r'wireguard://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    'mtproto': re.compile(r'(?:tg://proxy\?[^\s<>"\']+|https://t\.me/proxy\?[^\s<>"\']+)'),
}

HEADERS = {
    'User-Agent': CONFIG['user_agent'],
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
}

# ============================================================================
# Utility Functions
# ============================================================================

def setup_session() -> requests.Session:
    """ایجاد HTTP Session با connection pooling"""
    session = requests.Session()
    session.headers.update(HEADERS)
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=CONFIG['max_workers'],
        pool_maxsize=CONFIG['max_workers'] * 2,
        max_retries=CONFIG['max_retries']
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def clean_text(text: str) -> str:
    """پاکسازی و نرمال‌سازی متن"""
    if not text:
        return ""
    text = html.unescape(text)
    text = unquote(text)
    return text

def _add_b64_padding(s: str) -> str:
    """افزودن پدینگ صحیح base64"""
    padding_needed = (4 - len(s) % 4) % 4
    return s + '=' * padding_needed

def is_valid_vmess(config: str) -> bool:
    """اعتبارسنجی کانفیگ VMess"""
    try:
        base64_part = config.replace('vmess://', '')
        if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', base64_part):
            return False
        decoded = base64.b64decode(_add_b64_padding(base64_part)).decode('utf-8', errors='ignore')
        data = json.loads(decoded)
        required_fields = ['v', 'ps', 'add', 'port', 'id']
        if not all(field in data for field in required_fields):
            return False
        port = int(data.get('port', 0))
        return 1 <= port <= 65535
    except Exception:
        return False

def is_valid_mtproto(config: str) -> bool:
    """اعتبارسنجی لینک MTProto"""
    try:
        if not (config.startswith('tg://proxy?') or config.startswith('https://t.me/proxy?')):
            return False
        parsed = urlparse(config)
        params = parse_qs(parsed.query)
        if not all(k in params and params[k] for k in ('server', 'port', 'secret')):
            return False
        port = int(params['port'][0])
        if not (1 <= port <= 65535):
            return False
        secret = params['secret'][0]
        return len(secret) >= 16
    except Exception:
        return False

def is_valid_port(config: str) -> bool:
    """اعتبارسنجی پورت در URI"""
    try:
        parsed = urlparse(config)
        if parsed.port:
            return 1 <= parsed.port <= 65535
        return True
    except Exception:
        return True

def extract_configs_from_text(text: str) -> Dict[str, Set[str]]:
    """استخراج کانفیگ‌ها از متن"""
    configs = {protocol: set() for protocol in SUPPORTED_PROTOCOLS}
    if not text:
        return configs
    cleaned_text = clean_text(text)
    
    for protocol, pattern in PROTOCOL_PATTERNS.items():
        try:
            matches = pattern.findall(cleaned_text)
            for match in matches:
                cleaned = match.strip().rstrip('.,;!?)]\'"')
                if len(cleaned) > 15:
                    if protocol == 'vmess':
                        if is_valid_vmess(cleaned):
                            configs[protocol].add(cleaned)
                    elif protocol == 'mtproto':
                        if is_valid_mtproto(cleaned):
                            configs[protocol].add(cleaned)
                    else:
                        if is_valid_port(cleaned):
                            configs[protocol].add(cleaned)
        except Exception as e:
            logger.debug(f"خطا در استخراج {protocol}: {e}")
    
    return configs

def decode_base64_content(content: str) -> str:
    """رمزگشایی محتوای base64"""
    try:
        content = content.strip()
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        for line in lines:
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', line) and len(line) > 20:
                try:
                    decoded = base64.b64decode(_add_b64_padding(line)).decode('utf-8', errors='ignore')
                    if len(decoded) > 10 and any(proto + '://' in decoded for proto in SUPPORTED_PROTOCOLS):
                        return decoded
                except Exception:
                    continue
        
        if re.match(r'^[A-Za-z0-9+/=\s]+$', content):
            clean_content = re.sub(r'\s+', '', content)
            try:
                decoded = base64.b64decode(_add_b64_padding(clean_content)).decode('utf-8', errors='ignore')
                if len(decoded) > 10:
                    return decoded
            except Exception:
                pass
    except Exception:
        pass
    return content

# ============================================================================
# Scrapers
# ============================================================================

def scrape_telegram_channel(session: requests.Session, channel: str) -> Dict[str, Set[str]]:
    """اسکرپ کانال تلگرام"""
    url = f"{CONFIG['telegram_base_url']}{channel}"
    configs = {protocol: set() for protocol in SUPPORTED_PROTOCOLS}
    
    try:
        response = session.get(url, timeout=CONFIG['timeout'])
        if response.status_code != 200:
            logger.warning(f"❌ {channel}: HTTP {response.status_code}")
            return configs
        
        response.encoding = 'utf-8'
        soup = BeautifulSoup(response.text, 'lxml')
        messages = soup.find_all('div', class_='tgme_widget_message_text')
        
        for message in messages:
            text = message.get_text(separator=' ', strip=True)
            if text:
                extracted = extract_configs_from_text(text)
                for protocol in configs:
                    configs[protocol].update(extracted[protocol])
            
            for link in message.find_all('a', href=True):
                extracted = extract_configs_from_text(link['href'])
                for protocol in configs:
                    configs[protocol].update(extracted[protocol])
            
            for code_block in message.find_all(['pre', 'code']):
                extracted = extract_configs_from_text(code_block.get_text())
                for protocol in configs:
                    configs[protocol].update(extracted[protocol])
        
        total = sum(len(configs[p]) for p in configs)
        logger.info(f"✅ {channel}: {total} کانفیگ/پروکسی")
        
    except Exception as e:
        logger.error(f"❌ خطا در {channel}: {e}")
    
    return configs

def scrape_subscription_source(session: requests.Session, source_url: str) -> Dict[str, Set[str]]:
    """اسکرپ منبع subscription"""
    configs = {protocol: set() for protocol in SUPPORTED_PROTOCOLS}
    
    try:
        response = session.get(source_url, timeout=CONFIG['timeout'])
        if response.status_code != 200:
            logger.warning(f"❌ {source_url}: HTTP {response.status_code}")
            return configs
        
        response.encoding = 'utf-8'
        content = response.text.strip()
        decoded_content = decode_base64_content(content)
        
        texts_to_check = [content]
        if decoded_content != content:
            texts_to_check.append(decoded_content)
        
        for text in texts_to_check:
            extracted = extract_configs_from_text(text)
            for protocol in configs:
                configs[protocol].update(extracted[protocol])
            
            for line in text.split('\n'):
                if line.strip():
                    extracted = extract_configs_from_text(line)
                    for protocol in configs:
                        configs[protocol].update(extracted[protocol])
        
        total = sum(len(configs[p]) for p in configs)
        if total > 0:
            logger.info(f"✅ {source_url.split('/')[-1][:40]}: {total} کانفیگ/پروکسی")
        
    except Exception as e:
        logger.error(f"❌ خطا در منبع {source_url}: {e}")
    
    return configs

# ============================================================================
# File Management
# ============================================================================

def load_json_file(filename: str) -> dict:
    """بارگذاری فایل JSON"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"⚠️ فایل {filename} یافت نشد - مقدار خالی")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"❌ خطای JSON در {filename}: {e}")
        return {}
    except Exception as e:
        logger.error(f"❌ خطا در {filename}: {e}")
        return {}

def save_configs(configs: Dict[str, Set[str]], output_dir: str) -> Dict[str, int]:
    """ذخیره کانفیگ‌ها در فایل‌ها"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    output_files = set()
    stats = {}
    
    # ذخیره فایل به ازای هر پروتکل
    for protocol in SUPPORTED_PROTOCOLS:
        config_set = configs.get(protocol, set())
        stats[protocol] = len(config_set)
        if config_set:
            filepath = output_path / f"{protocol}.txt"
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(config_set)) + '\n')
            output_files.add(filepath.name)
            logger.info(f"💾 {protocol}.txt: {len(config_set)} آیتم")
    
    # ساخت config.txt (بدون MTProto)
    all_configs = []
    for protocol in SUPPORTED_PROTOCOLS:
        if protocol != 'mtproto':
            all_configs.extend(sorted(configs.get(protocol, set())))
    
    stats['config'] = len(all_configs)
    if all_configs:
        filepath = output_path / "config.txt"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_configs) + '\n')
        output_files.add("config.txt")
        logger.info(f"💾 config.txt: {len(all_configs)} کانفیگ")
    
    # ساخت config_lite.txt
    lite_configs = all_configs[:CONFIG['lite_config_count']]
    stats['config_lite'] = len(lite_configs)
    if lite_configs:
        filepath = output_path / "config_lite.txt"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lite_configs) + '\n')
        output_files.add("config_lite.txt")
        logger.info(f"💾 config_lite.txt: {len(lite_configs)} کانفیگ")
    
    # پاکسازی فایل‌های قدیمی
    for txt_file in output_path.glob('*.txt'):
        if txt_file.name not in output_files:
            if txt_file.stem in SUPPORTED_PROTOCOLS or txt_file.stem in ('config', 'config_lite'):
                try:
                    txt_file.unlink()
                    logger.info(f"🗑️ حذف فایل قدیمی: {txt_file.name}")
                except Exception as e:
                    logger.warning(f"⚠️ عدم حذف {txt_file.name}: {e}")
    
    return stats

# ============================================================================
# Dynamic README Generator
# ============================================================================

def generate_readme(stats: Dict[str, int]):
    """تولید README پویا"""
    owner = CONFIG['repo_owner']
    repo = CONFIG['repo_name']
    branch = CONFIG['branch']
    raw_base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}"
    now_utc = datetime.utcnow()
    update_time = now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    config_total = stats.get('config', 0)
    
    readme = f"""# 🚀 Auto Sub - V2Ray & MTProto Collector

> **آپدیت خودکار هر ۲ ساعت | آخرین آپدیت: `{update_time}`**

## 📊 آمار پروتکل‌ها و لینک‌های Raw

| پروتکل | تعداد | لینک دانلود |
|--------|-------|------------|
"""
    for protocol in SUPPORTED_PROTOCOLS:
        count = stats.get(protocol, 0)
        display_name = PROTOCOL_DISPLAY_NAMES.get(protocol, protocol)
        link = f"{raw_base}/{protocol}.txt"
        status = "✅" if count > 0 else "❌"
        readme += f"| **{display_name}** | {count:,} | [{status} Raw]({link}) |\n"
        
    readme += f"""| **🎯 همه V2Ray** | **{config_total:,}** | [📥 Raw]({raw_base}/config.txt) |
| **🪶 نسخه سبک** | **{stats.get('config_lite', 0)}** | [📥 Raw]({raw_base}/config_lite.txt) |

---

## 🔗 لینک‌های Subscription (آماده کپی)

**📦 لینک اصلی (V2Ray):**

<{raw_base}/config.txt>

**📱 پروکسی تلگرام (MTProto):**

<{raw_base}/mtproto.txt>

---

## 📱 راهنمای استفاده

### کلاینت‌های پیشنهادی:
- **اندروید:** v2rayNG, Hiddify, NekoBox
- **iOS:** Streisand, Shadowrocket, Hiddify
- **ویندوز:** v2rayN, Hiddify, NekoRay
- **تلگرام (MTProto):** خود تلگرام با کلیک روی لینک پروکسی

### نکته مهم:
- لینک‌های MTProto را مستقیماً در تلگرام باز کنید تا به عنوان پروکسی اضافه شوند.
- لینک‌های V2Ray را در کلاینت مربوطه به عنوان Subscription وارد کنید.

---

## ⚙️ تنظیمات

این پروژه از Environment Variables پشتیبانی می‌کند:

| متغیر | توضیح | پیش‌فرض |
|-------|-------|---------|
| `CHANNELS_FILE` | فایل لیست کانال‌ها | `channels.json` |
| `SOURCES_FILE` | فایل لیست منابع | `sources.json` |
| `MAX_WORKERS` | تعداد thread های همزمان | `10` |
| `TIMEOUT` | زمان انتظار برای درخواست‌ها | `20` |
| `LITE_CONFIG_COUNT` | تعداد کانفیگ در نسخه سبک | `15` |
| `REPO_OWNER` | نام کاربری GitHub | `Par123456` |
| `REPO_NAME` | نام repository | `auto-sub` |
| `BRANCH` | شاخه branch | `main` |

---

## 📝 لایسنس

این پروژه تحت لایسنس MIT منتشر شده است.
"""
    
    try:
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
        logger.info("📝 README.md با موفقیت آپدیت شد!")
    except Exception as e:
        logger.error(f"❌ خطا در نوشتن README: {e}")

# ============================================================================
# Main Function - کاملاً مقاوم در برابر خطا
# ============================================================================

def main() -> int:
    """تابع اصلی اجرا"""
    print("=" * 70)
    print("🚀 V2Ray & MTProto Collector - نسخه نهایی")
    print("=" * 70)
    
    # 🔴 try-except سراسری - هیچ exceptionی نباید باعث exit code 1 شود
    try:
        session = setup_session()
    except Exception as e:
        logger.error(f"❌ خطا در ایجاد session: {e}")
        logger.error(traceback.format_exc())
        return 0
    
    try:
        channels_data = load_json_file(CONFIG['channels_file'])
        sources_data = load_json_file(CONFIG['sources_file'])
    except Exception as e:
        logger.error(f"❌ خطا در بارگذاری فایل‌های JSON: {e}")
        logger.error(traceback.format_exc())
        channels_data = {}
        sources_data = {}
    
    channels = list(set([c for c in channels_data.get('channels', []) if c and isinstance(c, str)]))
    sources = list(set([s for s in sources_data.get('sources', []) if s and isinstance(s, str)]))
    
    logger.info(f"📡 شروع اسکرپ {len(channels)} کانال و {len(sources)} منبع...")
    
    all_configs = {protocol: set() for protocol in SUPPORTED_PROTOCOLS}
    
    try:
        if channels or sources:
            with ThreadPoolExecutor(max_workers=CONFIG['max_workers']) as executor:
                futures = [executor.submit(scrape_telegram_channel, session, ch) for ch in channels]
                futures += [executor.submit(scrape_subscription_source, session, src) for src in sources]
                
                for future in as_completed(futures):
                    try:
                        res = future.result()
                        for p in all_configs:
                            all_configs[p].update(res.get(p, set()))
                    except Exception as e:
                        logger.warning(f"⚠️ خطا در پردازش future: {e}")
    except Exception as e:
        logger.error(f"❌ خطا در اجرای ThreadPoolExecutor: {e}")
        logger.error(traceback.format_exc())
    
    total = sum(len(all_configs[p]) for p in SUPPORTED_PROTOCOLS)
    logger.info(f"📊 مجموع کل: {total:,} آیتم یکتا")
    
    if total == 0:
        logger.warning("⚠️ هیچ کانفیگی پیدا نشد - فایل‌ها آپدیت نمی‌شوند")
        return 0  # ✅ همیشه 0 برمی‌گردانیم
    
    try:
        stats = save_configs(all_configs, CONFIG['output_dir'])
        generate_readme(stats)
    except Exception as e:
        logger.error(f"❌ خطا در ذخیره فایل‌ها: {e}")
        logger.error(traceback.format_exc())
        return 0  # ✅ حتی در صورت خطا، 0 برمی‌گردانیم
    
    logger.info("✅ عملیات با موفقیت کامل شد!")
    return 0

if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except Exception as e:
        # 🔴 آخرین سنگر: هر exceptionی که از main فرار کند اینجا catch می‌شود
        logger.error(f"❌ خطای ناشناخته در سطح بالا: {e}")
        logger.error(traceback.format_exc())
        sys.exit(0)  # ✅ حتی اینجا هم 0 برمی‌گردانیم
