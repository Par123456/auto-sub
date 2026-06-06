#!/usr/bin/env python3
"""
V2Ray Config Collector - نسخه باگ‌فری
جمع‌آوری خودکار کانفیگ‌های V2Ray از کانال‌های تلگرام و منابع دیگر
"""

import json
import re
import base64
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Set, Dict
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup

# ============================================================================
# Configuration
# ============================================================================

CONFIG = {
    'channels_file': 'channels.json',
    'sources_file': 'sources.json',
    'output_dir': '.',
    'max_workers': 10,
    'timeout': 20,
    'max_retries': 3,
    'telegram_base_url': 'https://t.me/s/',
    'lite_config_count': 15,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

SUPPORTED_PROTOCOLS = [
    'vmess', 'vless', 'trojan', 'ss', 'ssr', 'tuic',
    'socks', 'juicity', 'reality', 'hysteria', 'hysteria2',
    'ssh', 'wireguard'
]

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
}

HEADERS = {
    'User-Agent': CONFIG['user_agent'],
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
}

# ============================================================================
# Utility Functions
# ============================================================================

def setup_session() -> requests.Session:
    """ساخت session با تنظیمات بهینه"""
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
    """پاکسازی متن از HTML entities و URL encoding"""
    if not text:
        return ""
    # Decode HTML entities (&amp; -> &)
    text = html.unescape(text)
    # Decode URL encoding (%20 -> space)
    text = unquote(text)
    return text


def is_valid_vmess(config: str) -> bool:
    """بررسی معتبر بودن کانفیگ vmess"""
    try:
        base64_part = config.replace('vmess://', '')
        # بررسی ساختار base64
        if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', base64_part):
            return False
        # تلاش برای decode
        decoded = base64.b64decode(base64_part + '==').decode('utf-8', errors='ignore')
        # باید JSON معتبر باشه
        data = json.loads(decoded)
        # بررسی فیلدهای ضروری
        required_fields = ['v', 'ps', 'add', 'port', 'id']
        return all(field in data for field in required_fields)
    except Exception:
        return False


def extract_configs_from_text(text: str) -> Dict[str, Set[str]]:
    """استخراج کانفیگ‌های V2Ray از متن"""
    configs = {protocol: set() for protocol in SUPPORTED_PROTOCOLS}
    
    if not text:
        return configs
    
    cleaned_text = clean_text(text)
    
    for protocol, pattern in PROTOCOL_PATTERNS.items():
        matches = pattern.findall(cleaned_text)
        for match in matches:
            cleaned = match.strip()
            if len(cleaned) > 15:
                if protocol == 'vmess':
                    if is_valid_vmess(cleaned):
                        configs[protocol].add(cleaned)
                else:
                    configs[protocol].add(cleaned)
    
    return configs


def decode_base64_content(content: str) -> str:
    """تلاش برای دیکد کردن محتوای base64"""
    try:
        content = content.strip()
        
        # اگر چندخطی بود، هر خط رو چک می‌کنیم
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        for line in lines:
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', line) and len(line) > 20:
                try:
                    decoded = base64.b64decode(line).decode('utf-8', errors='ignore')
                    if len(decoded) > 10 and any(proto + '://' in decoded for proto in SUPPORTED_PROTOCOLS):
                        return decoded
                except Exception:
                    continue
        
        # چک کردن کل محتوا به عنوان یک base64
        if re.match(r'^[A-Za-z0-9+/=\s]+$', content):
            clean_content = re.sub(r'\s+', '', content)
            try:
                decoded = base64.b64decode(clean_content).decode('utf-8', errors='ignore')
                if len(decoded) > 10:
                    return decoded
            except Exception:
                pass
    except Exception:
        pass
    
    return content


# ============================================================================
# Telegram Scraper
# ============================================================================

def scrape_telegram_channel(session: requests.Session, channel: str) -> Dict[str, Set[str]]:
    """جمع‌آوری کانفیگ‌ها از یک کانال تلگرام"""
    url = f"{CONFIG['telegram_base_url']}{channel}"
    configs = {protocol: set() for protocol in SUPPORTED_PROTOCOLS}
    
    try:
        response = session.get(url, timeout=CONFIG['timeout'])
        if response.status_code != 200:
            print(f"  ❌ خطا در {channel}: HTTP {response.status_code}")
            return configs
        
        response.encoding = 'utf-8'
        soup = BeautifulSoup(response.text, 'lxml')
        
        # پیدا کردن همه پیام‌ها
        messages = soup.find_all('div', class_='tgme_widget_message_text')
        
        for message in messages:
            # متن عادی
            text = message.get_text(separator=' ', strip=True)
            if text:
                extracted = extract_configs_from_text(text)
                for protocol in configs:
                    configs[protocol].update(extracted[protocol])
            
            # لینک‌های داخل پیام
            for link in message.find_all('a', href=True):
                href = link['href']
                extracted = extract_configs_from_text(href)
                for protocol in configs:
                    configs[protocol].update(extracted[protocol])
            
            # بلوک‌های کد (pre, code) - خیلی مهم!
            for code_block in message.find_all(['pre', 'code']):
                code_text = code_block.get_text()
                if code_text:
                    extracted = extract_configs_from_text(code_text)
                    for protocol in configs:
                        configs[protocol].update(extracted[protocol])
        
        total = sum(len(configs[p]) for p in configs)
        print(f"  ✅ {channel}: {total} کانفیگ")
        
    except requests.exceptions.RequestException as e:
        print(f"  ❌ خطای شبکه در {channel}: {e}")
    except Exception as e:
        print(f"  ❌ خطای غیرمنتظره در {channel}: {e}")
    
    return configs


# ============================================================================
# Source Scraper
# ============================================================================

def scrape_subscription_source(session: requests.Session, source_url: str) -> Dict[str, Set[str]]:
    """جمع‌آوری کانفیگ‌ها از یک منبع سابسکریپشن"""
    configs = {protocol: set() for protocol in SUPPORTED_PROTOCOLS}
    
    try:
        response = session.get(source_url, timeout=CONFIG['timeout'])
        if response.status_code != 200:
            print(f"  ❌ خطا در {source_url}: HTTP {response.status_code}")
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
                line = line.strip()
                if line:
                    extracted = extract_configs_from_text(line)
                    for protocol in configs:
                        configs[protocol].update(extracted[protocol])
        
        total = sum(len(configs[p]) for p in configs)
        if total > 0:
            # فقط اسم فایل رو چاپ می‌کنیم نه کل URL رو
            filename = source_url.split('/')[-1][:40]
            print(f"  ✅ {filename}: {total} کانفیگ")
        
    except requests.exceptions.RequestException as e:
        print(f"  ❌ خطای شبکه: {e}")
    except Exception as e:
        print(f"  ❌ خطای غیرمنتظره: {e}")
    
    return configs


# ============================================================================
# Main Collector
# ============================================================================

def load_json_file(filename: str) -> dict:
    """بارگذاری فایل JSON"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"  ⚠️ فایل {filename} پیدا نشد")
        return {}
    except json.JSONDecodeError as e:
        print(f"  ❌ خطا در خواندن {filename}: {e}")
        return {}


def save_configs(configs: Dict[str, Set[str]], output_dir: str):
    """ذخیره کانفیگ‌ها در فایل‌های جداگانه"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    output_files = set()
    
    # ذخیره هر پروتکل
    for protocol in SUPPORTED_PROTOCOLS:
        config_set = configs.get(protocol, set())
        if config_set:
            sorted_configs = sorted(config_set)
            filepath = output_path / f"{protocol}.txt"
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_configs) + '\n')
            output_files.add(filepath.name)
            print(f"  💾 {protocol}.txt: {len(sorted_configs)} کانفیگ")
    
    # فایل همه پروتکل‌ها
    all_configs = []
    for protocol in SUPPORTED_PROTOCOLS:
        all_configs.extend(sorted(configs.get(protocol, set())))
    
    if all_configs:
        filepath = output_path / "config.txt"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_configs) + '\n')
        output_files.add("config.txt")
        print(f"  💾 config.txt: {len(all_configs)} کانفیگ")
    
    # نسخه سبک
    lite_configs = []
    for protocol in SUPPORTED_PROTOCOLS:
        protocol_configs = sorted(configs.get(protocol, set()))[:CONFIG['lite_config_count']]
        lite_configs.extend(protocol_configs)
    
    if lite_configs:
        filepath = output_path / "config_lite.txt"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lite_configs) + '\n')
        output_files.add("config_lite.txt")
        print(f"  💾 config_lite.txt: {len(lite_configs)} کانفیگ")
    
    # حذف فایل‌های قدیمی که دیگه کانفیگ ندارن
    for txt_file in output_path.glob('*.txt'):
        if txt_file.name not in output_files:
            # فقط فایل‌های مربوط به پروتکل‌ها رو حذف می‌کنیم
            if txt_file.stem in SUPPORTED_PROTOCOLS:
                try:
                    txt_file.unlink()
                    print(f"  🗑️ حذف فایل قدیمی: {txt_file.name}")
                except Exception:
                    pass


def main():
    """تابع اصلی"""
    print("=" * 60)
    print("🚀 V2Ray Config Collector - نسخه باگ‌فری")
    print("=" * 60)
    
    session = setup_session()
    
    channels_data = load_json_file(CONFIG['channels_file'])
    sources_data = load_json_file(CONFIG['sources_file'])
    
    # حذف تکراری‌ها با set
    channels = list(set(channels_data.get('channels', [])))
    sources = list(set(sources_data.get('sources', [])))
    
    # حذف مقادیر خالی
    channels = [c for c in channels if c and isinstance(c, str) and c.strip()]
    sources = [s for s in sources if s and isinstance(s, str) and s.strip()]
    
    print(f"\n📡 تعداد کانال‌های یکتا: {len(channels)}")
    print(f"🔗 تعداد منابع یکتا: {len(sources)}")
    
    # جمع‌آوری از کانال‌های تلگرام
    print("\n" + "-" * 60)
    print("📱 شروع جمع‌آوری از کانال‌های تلگرام...")
    print("-" * 60)
    
    all_configs = {protocol: set() for protocol in SUPPORTED_PROTOCOLS}
    
    with ThreadPoolExecutor(max_workers=CONFIG['max_workers']) as executor:
        future_to_channel = {
            executor.submit(scrape_telegram_channel, session, channel): channel
            for channel in channels
        }
        
        for future in as_completed(future_to_channel):
            channel = future_to_channel[future]
            try:
                channel_configs = future.result()
                for protocol in all_configs:
                    all_configs[protocol].update(channel_configs.get(protocol, set()))
            except Exception as e:
                print(f"  ❌ خطای غیرمنتظره در {channel}: {e}")
    
    # جمع‌آوری از منابع سابسکریپشن
    print("\n" + "-" * 60)
    print("🌐 شروع جمع‌آوری از منابع سابسکریپشن...")
    print("-" * 60)
    
    with ThreadPoolExecutor(max_workers=CONFIG['max_workers']) as executor:
        future_to_source = {
            executor.submit(scrape_subscription_source, session, source): source
            for source in sources
        }
        
        for future in as_completed(future_to_source):
            try:
                source_configs = future.result()
                for protocol in all_configs:
                    all_configs[protocol].update(source_configs.get(protocol, set()))
            except Exception as e:
                print(f"  ❌ خطای غیرمنتظره: {e}")
    
    # نمایش آمار
    print("\n" + "=" * 60)
    print("📊 آمار جمع‌آوری:")
    print("=" * 60)
    
    total_configs = 0
    for protocol in SUPPORTED_PROTOCOLS:
        count = len(all_configs[protocol])
        total_configs += count
        if count > 0:
            print(f"  {protocol.upper()}: {count:,}")
    
    print(f"\n  مجموع کل: {total_configs:,} کانفیگ یکتا")
    
    if total_configs == 0:
        print("\n  ⚠️ هیچ کانفیگی پیدا نشد! لطفاً اتصال اینترنت رو بررسی کنید.")
        return 1
    
    # ذخیره نتایج
    print("\n" + "-" * 60)
    print("💾 ذخیره نتایج...")
    print("-" * 60)
    
    save_configs(all_configs, CONFIG['output_dir'])
    
    print("\n" + "=" * 60)
    print("✅ جمع‌آوری با موفقیت کامل شد!")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    exit(main())
