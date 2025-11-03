from flask import Flask, request, jsonify
import requests
import hashlib
import time
from fake_useragent import UserAgent

app = Flask(__name__)

# Fake UserAgent oluşturucu
ua = UserAgent()

def get_user_ip_hash():
    try:
        ip_response = requests.get('https://api.ipify.org', timeout=5)
        user_ip = ip_response.text
    except:
        user_ip = request.remote_addr
    
    ip_hash = hashlib.md5(user_ip.encode()).hexdigest()[:8]
    return ip_hash, user_ip

def get_random_headers(referer):
    """Her kullanıcı için random headers oluştur"""
    return {
        'authority': 'leofame.com',
        'accept': '*/*',
        'accept-language': 'tr-TR,tr;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://leofame.com',
        'referer': referer,
        'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': ua.random  # Her istekte random user agent
    }

def send_leofame_request(service, link, user_ip):
    """LeoFame servislerine GET isteği gönder"""
    
    base_url = "https://leofame.com"
    endpoints = {
        'instagram_likes': '/free-instagram-likes',
        'tiktok_likes': '/free-tiktok-likes',
        'instagram_followers': '/free-instagram-followers',
        'instagram_views': '/free-instagram-views',
        'instagram_saves': '/free-instagram-saves',
        'instagram_shares': '/free-instagram-shares',
        'instagram_story_views': '/free-instagram-story-views',
        'tiktok_views': '/free-tiktok-views',
        'tiktok_followers': '/free-tiktok-followers',
        'youtube_likes': '/free-youtube-likes',
        'spotify_saves': '/free-spotify-saves'
    }
    
    cookies = {
        'trsdb': '1',
        'token': '761991ff786b3aabeb9944728c8fa629',
        'ci_session': 'd23b9327b6ebdd6578b0709f8437d736dba475ce'
    }
    
    # IP'ye özel parametreler
    params = {
        'api': '1',
        'user_ip': user_ip,
        'ip_hash': hashlib.md5(user_ip.encode()).hexdigest()[:8],
        'free_link': link
    }
    
    # Servise göre ek parametreler
    service_config = {
        'instagram_likes': {'quantity': '75', 'speed': '5', 'wait_time': 300},
        'tiktok_likes': {'quantity': '30', 'wait_time': 80},
        'instagram_followers': {'quantity': '10', 'wait_time': 86400},
        'instagram_views': {'quantity': '2500', 'wait_time': 86400},
        'instagram_saves': {'quantity': '150', 'wait_time': 86400},
        'instagram_shares': {'quantity': '300', 'wait_time': 86400},
        'instagram_story_views': {'quantity': '100', 'wait_time': 86400},
        'tiktok_views': {'quantity': '400', 'wait_time': 86400},
        'tiktok_followers': {'quantity': '20', 'wait_time': 86400},
        'youtube_likes': {'quantity': '50', 'wait_time': 86400},
        'spotify_saves': {'quantity': '100', 'wait_time': 86400}
    }
    
    if service in service_config:
        params.update({k: v for k, v in service_config[service].items() if k != 'wait_time'})
    
    try:
        url = base_url + endpoints[service]
        referer = url
        
        # Her kullanıcı için random headers
        headers = get_random_headers(referer)
        
        response = requests.get(url, params=params, cookies=cookies, headers=headers, timeout=30)
        
        return {
            'status': 'success' if response.status_code == 200 else 'error',
            'service': service,
            'link': link,
            'user_ip': user_ip,
            'user_agent': headers['user-agent'],  # Hangi user agent kullanıldı
            'response_code': response.status_code,
            'wait_time': service_config.get(service, {}).get('wait_time', 300),
            'message': 'İstek başarıyla gönderildi' if response.status_code == 200 else 'Hata oluştu'
        }
    except Exception as e:
        return {
            'status': 'error',
            'service': service,
            'link': link,
            'user_ip': user_ip,
            'error': str(e)
        }

# API Endpoint'leri
@app.route('/api/services', methods=['GET'])
def get_services():
    """Mevcut servisleri listele"""
    services = {
        'instagram_likes': {'name': 'Instagram Beğeni', 'quota': 75, 'wait_time': 300},
        'tiktok_likes': {'name': 'TikTok Beğeni', 'quota': 30, 'wait_time': 80},
        'instagram_followers': {'name': 'Instagram Takipçi', 'quota': 10, 'wait_time': 86400},
        'instagram_views': {'name': 'Instagram Görüntüleme', 'quota': 2500, 'wait_time': 86400},
        'instagram_saves': {'name': 'Instagram Kaydetme', 'quota': 150, 'wait_time': 86400},
        'instagram_shares': {'name': 'Instagram Paylaşım', 'quota': 300, 'wait_time': 86400},
        'instagram_story_views': {'name': 'Instagram Story Görüntüleme', 'quota': 100, 'wait_time': 86400},
        'tiktok_views': {'name': 'TikTok Görüntüleme', 'quota': 400, 'wait_time': 86400},
        'tiktok_followers': {'name': 'TikTok Takipçi', 'quota': 20, 'wait_time': 86400},
        'youtube_likes': {'name': 'YouTube Beğeni', 'quota': 50, 'wait_time': 86400},
        'spotify_saves': {'name': 'Spotify Kaydetme', 'quota': 100, 'wait_time': 86400}
    }
    return jsonify(services)

@app.route('/api/send', methods=['GET'])
def send_request():
    """Servis isteği gönder"""
    service = request.args.get('service')
    link = request.args.get('link')
    
    if not service or not link:
        return jsonify({'status': 'error', 'message': 'Service ve link parametreleri gereklidir'})
    
    user_ip = request.remote_addr
    result = send_leofame_request(service, link, user_ip)
    
    return jsonify(result)

@app.route('/api/status', methods=['GET'])
def get_status():
    """API durumunu kontrol et"""
    user_ip = request.remote_addr
    ip_hash = hashlib.md5(user_ip.encode()).hexdigest()[:8]
    
    # Random user agent oluştur
    current_ua = ua.random
    
    return jsonify({
        'status': 'active',
        'user_ip': user_ip,
        'ip_hash': ip_hash,
        'user_agent': current_ua,
        'server_time': time.time(),
        'message': 'NABISYSTEM API Aktif'
    })

@app.route('/')
def home():
    return jsonify({
        'message': 'NABISYSTEM Social Media API',
        'version': '1.0',
        'developer': 'NABISYSTEM',
        'endpoints': {
            '/api/services': 'GET - Servis listesi',
            '/api/send': 'GET - İstek gönder',
            '/api/status': 'GET - API durumu'
        },
        'usage': '/api/send?service=instagram_likes&link=URL'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
