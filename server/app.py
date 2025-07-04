from flask import Flask, render_template, send_file, jsonify, abort, request, send_from_directory
import requests
from bs4 import BeautifulSoup
import datetime
import time
import os
import re
import threading
import random
import subprocess
import logging
import json
from functools import wraps
import base64

app = Flask(__name__)

# ==================== 配置部分 ====================
# 日志配置
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# 控制台日志处理器
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# 文件日志处理器
file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.WARNING)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

# 添加处理器
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# 安全相关配置
BLACKLIST_FILE = 'blacklisted_ips.json'
WHITELIST_FILE = 'whitelisted_ips.json'
MAX_404_ATTEMPTS = 10
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'yourpassword'

# ==================== 全局变量 ====================
ip_404_counts = {}
blacklisted_ips = set()
whitelisted_ips = set()
lock = threading.Lock()
start_time = datetime.datetime.now()
cached_server_counts = None
last_update_time = None
visit_count = 0

# ==================== 初始化函数 ====================
def load_ip_lists():
    global blacklisted_ips, whitelisted_ips, visit_count
    
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, 'r') as f:
                data = json.load(f)
                blacklisted_ips = set(data.get('blacklisted_ips', []))
                logging.info(f"已加载 {len(blacklisted_ips)} 个封禁IP")
        except Exception as e:
            logging.error(f"加载封禁IP列表失败: {e}")

    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                data = json.load(f)
                whitelisted_ips = set(data.get('whitelisted_ips', []))
                logging.info(f"已加载 {len(whitelisted_ips)} 个白名单IP")
        except Exception as e:
            logging.error(f"加载白名单IP列表失败: {e}")

    if os.path.exists('visit_count.json'):
        try:
            with open('visit_count.json', 'r') as f:
                visit_count = json.load(f).get('visit_count', 0)
        except Exception as e:
            logging.error(f"加载访问量失败: {e}")

    # 确保模板目录存在
    if not os.path.exists('templates'):
        os.makedirs('templates')
        logging.warning("已创建templates目录")
    
    # 确保模板文件存在
    if not os.path.exists('templates/index.html'):
        with open('templates/index.html', 'w', encoding='utf-8') as f:
            f.write('''<!DOCTYPE html>
<html lang="zh-cn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XXX服务器状态查询</title>
    <!-- 引用本地 Bootstrap CSS 文件 -->
    <link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap.min.css') }}">
    <style>
        h1 {
            font-family: Arial, sans-serif;
            color: #4CAF50;
            text-align: center;
            margin-bottom: 20px;
        }
        table {
            margin: 20px auto;
            border-radius: 10px;
            background-color: white;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 80%;
        }
        table tbody tr {
            animation: slideFromRight 1s ease;
        }
        @keyframes slideFromRight {
            from { transform: translateX(100%); }
            to { transform: translateX(0); }
        }
        table tbody tr:hover {
            background-color: #f0f0f0;
        }
        .server-box {
            border-radius: 10px;
            padding: 10;
            background-color: white;
            width: 200px;
            margin: 10px 0;
        }
        #time {
            text-align: center;
            font-size: 20px;
            font-weight: bold;
            color: #555;
            margin-top: 20px;
        }
        .suggestion {
            text-align: center;
            color: red;
            margin-top: 10px;
            margin-bottom: 15px;
        }
        .download {
            text-decoration: underline;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            background-color: #f8f9fa;
            border-top: 1px solid #e9ecef;
        }
        .status-container {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 20px;
            margin-bottom: 20px;
        }
        .status-card {
            width: 300px;
            text-align: center;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card-title {
            font-size: 1.2rem;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .card-value {
            font-size: 1.5rem;
            color: #2c3e50;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <h1>XXX服务器状态</h1>
        <p class="suggestion">游玩时建议使用芒辉加速器<a href="/download" class="download">下载</a></p>

        <!-- 状态卡片 -->
        <div class="status-container">
            <!-- 插件一服卡片 -->
            <div class="status-card" style="background-color: #e9ecef;">
                <div class="card-title">插件一服</div>
                <div class="card-value" id="plugin_1_count">
                    {{ plugin_1_count if plugin_1_count else '获取中...' }}
                </div>
            </div>
            
            <!-- XXX卡片 -->
            <div class="status-card" style="background-color: #d1ecf1;">
                <div class="card-title">XXX</div>
                <div class="card-value" id="entertainment_14_0_count">
                    {{ entertainment_14_0_count if entertainment_14_0_count else '获取中...' }}
                </div>
            </div>
        </div>

        <div id="time">当前时间：{{ current_time }}</div>
    </div>

    <!-- 访问量统计 -->
    <div class="footer">
        网站总访问量：<span id="visit-count">{{ visit_count }}</span>
    </div>

    <!-- JavaScript 用于动态更新数据和时间 -->
    <script>
        // 更新时间
        function updateTime() {
            var currentTime = new Date();
            var hours = currentTime.getHours().toString().padStart(2, '0');
            var minutes = currentTime.getMinutes().toString().padStart(2, '0');
            var seconds = currentTime.getSeconds().toString().padStart(2, '0');
            var milliseconds = currentTime.getMilliseconds().toString().padStart(3, '0');

            document.getElementById('time').innerHTML = '当前时间：' + hours + ':' + minutes + ':' + seconds + ':' + milliseconds;
        }

        // 每100毫秒更新一次时间
        setInterval(updateTime, 100);

        // 更新数据
        function updateData() {
            fetch('/get_latest_data')  // 从后端获取最新数据
                .then(response => response.json())
                .then(data => {
                    // 更新插件服数据
                    document.getElementById('plugin_1_count').textContent = data.plugin_1_count || 'N/A';
                    
                    // 更新凛冬之塔数据
                    document.getElementById('entertainment_14_0_count').textContent = data.entertainment_14_0_count || 'N/A';
                    
                    // 更新访问量
                    document.getElementById('visit-count').textContent = data.visit_count;
                })
                .catch(error => console.error('Error fetching data:', error));
        }

        // 每5秒更新一次数据
        setInterval(updateData, 5000);

        // 页面加载时立即更新一次数据
        updateData();
    </script>
</body>
</html>''')
        logging.warning("已创建默认index.html模板")

# ==================== 安全功能函数 ====================
def block_ip_windows(ip):
    try:
        subprocess.run(
            f"netsh advfirewall firewall add rule name=\"Block {ip}\" "
            f"dir=in action=block remoteip={ip}",
            shell=True
        )
        logging.warning(f"[!] 已封禁IP: {ip}")
    except Exception as e:
        logging.warning(f"[!] 封禁IP失败: {e}")

def unblock_ip_windows(ip):
    try:
        subprocess.run(
            f"netsh advfirewall firewall delete rule name=\"Block {ip}\"",
            shell=True
        )
        logging.warning(f"[!] 已解除封禁IP: {ip}")
    except Exception as e:
        logging.warning(f"[!] 解除封禁失败: {e}")

def save_blacklist():
    try:
        with open(BLACKLIST_FILE, 'w') as f:
            json.dump({
                'blacklisted_ips': list(blacklisted_ips),
                'last_updated': datetime.datetime.now().isoformat()
            }, f, indent=2)
    except Exception as e:
        logging.error(f"保存封禁IP列表失败: {e}")

def save_whitelist():
    try:
        with open(WHITELIST_FILE, 'w') as f:
            json.dump({
                'whitelisted_ips': list(whitelisted_ips),
                'last_updated': datetime.datetime.now().isoformat()
            }, f, indent=2)
    except Exception as e:
        logging.error(f"保存白名单IP列表失败: {e}")

# ==================== 认证装饰器 ====================
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization')
        if not auth or not auth.startswith('Basic '):
            return jsonify({'error': '需要认证'}), 401
        
        try:
            credentials = base64.b64decode(auth[6:]).decode('utf-8')
            username, password = credentials.split(':', 1)
            if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
                return jsonify({'error': '认证失败'}), 401
        except:
            return jsonify({'error': '认证失败'}), 401
        
        return f(*args, **kwargs)
    return decorated

# ==================== 中间件 ====================
@app.before_request
def security_checks():
    ip = request.remote_addr
    path = request.path.lower()
    
    # 白名单IP直接放行
    if ip in whitelisted_ips:
        return
    
    # 检查IP是否在黑名单中
    if ip in blacklisted_ips:
        logging.warning(f"[封禁] 拦截黑名单IP {ip} 访问 {path}")
        abort(403, description="IP地址已被封禁")
    
    # 检查非常规字符
    if re.search(r'[^\x20-\x7e]', request.url):
        logging.warning(f"[混淆]拦截非常规字符请求 {ip} - {request.url[:50]}")
        abort(404)
    
    # 检查扫描器User-Agent
    bad_agents = ['sqlmap', 'nikto', 'hydra', 'zgrab', 'wpscan', 'dirbuster']
    ua = request.headers.get('User-Agent', '').lower()
    if any(agent in ua for agent in bad_agents):
        logging.warning(f"[混淆]拦截扫描器UA {ip} - {ua}")
        abort(404)
    
    # 检查可疑路径
    FAKE_PATHS = [
        '/admin', '/wp-login.php', '/.env', '/.git/config',
        '/api/v1/auth', '/console', '/phpmyadmin',
        '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
    ]
    if path in [p.lower() for p in FAKE_PATHS]:
        logging.warning(f"[混淆]触发虚假路径 {ip} - {path}")
        return jsonify({
            "status": "error",
            "message": "Access denied",
            "fake_flag": "flag{this_is_fake_do_not_submit}"
        }), 418
    
    # 检查可疑参数
    suspicious_params = ['/etc/passwd', 'union select', '<?php', 'exec(', 'system(']
    for param in request.values:
        if any(pattern in param.lower() for pattern in suspicious_params):
            logging.warning(f"[混淆]拦截恶意参数 {ip} - {param[:50]}")
            abort(404)

# ==================== 路由处理 ====================
@app.route('/')
def index():
    """首页路由"""
    try:
        global visit_count
        visit_count += 1
        
        # 保存访问量
        with open('visit_count.json', 'w') as f:
            json.dump({'visit_count': visit_count}, f)
        
        # 获取服务器数据
        server_counts = get_server_counts()
        
        return render_template('index.html',
                            plugin_1_count=server_counts['plugin_1_count'],
                            entertainment_14_0_count=server_counts['entertainment_14_0_count'],
                            current_time=get_current_time(),
                            visit_count=visit_count)
    
    except Exception as e:
        logging.error(f"首页渲染错误: {str(e)}")
        abort(500, description="服务器内部错误")

@app.route('/download')
def download():
    """下载页面路由"""
    return send_file('path/to/your/accelerator.exe', as_attachment=True)

@app.errorhandler(404)
def handle_404(error):
    ip = request.remote_addr
    path = request.path

    with lock:
        ip_404_counts[ip] = ip_404_counts.get(ip, 0) + 1
        logging.warning(f"[404] IP {ip} 访问了不存在的路径: {path} (总计 {ip_404_counts[ip]}次)")

        if (ip_404_counts[ip] >= MAX_404_ATTEMPTS and 
            ip not in blacklisted_ips and 
            ip not in whitelisted_ips):
            
            blacklisted_ips.add(ip)
            block_ip_windows(ip)
            save_blacklist()
            logging.warning(f"[封禁] 已永久封禁IP {ip} 并保存到文件")

    if path.startswith('/.git/'):
        return fake_git_response(path.split('/.git/')[1])
    
    fake_content, content_type = generate_fake_file(path)
    return fake_content, 404, {'Content-Type': content_type}

def fake_git_response(git_path):
    FAKE_GIT_CONTENT = {
        'HEAD': 'ref: refs/heads/master\n',
        'config': f"""[core]
        repositoryformatversion = 0
        filemode = false
        bare = false
        logallrefupdates = true
        [remote "origin"]
        url = git@github.com:fake-repo/{random.choice(['project1', 'project2'])}.git
        fetch = +refs/heads/*:refs/remotes/origin/*""",
        'description': 'Unnamed repository; edit this file to name it for gitweb.\n'
    }
    
    if git_path in FAKE_GIT_CONTENT:
        return FAKE_GIT_CONTENT[git_path], 200, {'Content-Type': 'text/plain'}
    
    if 'objects' in git_path:
        return os.urandom(20), 404, {
            'Content-Type': 'application/octet-stream',
            'X-Git-Error': 'invalid object'
        }
    
    fake_errors = ['Repository not found', 'Invalid git path', 'Access denied']
    return f"{random.choice(fake_errors)}\n", 404

def generate_fake_file(path):
    if path.endswith('.env'):
        return "APP_KEY=this_is_a_fake_key\nDB_PASSWORD=fake_password", 'text/plain'
    elif path.endswith('.xml'):
        return "<root><data>fake</data></root>", 'application/xml'
    elif path.endswith('.ico'):
        return os.urandom(16), 'image/x-icon'
    else:
        return "File not found", 'text/plain'

# ==================== 服务器状态路由 ====================
@app.route('/get_latest_data')
def get_latest_data():
    """获取服务器最新数据"""
    try:
        global visit_count
        server_counts = get_server_counts()
        current_time = get_current_time()

        response_data = {
            'plugin_1_count': server_counts.get('plugin_1_count', 'N/A'),
            'entertainment_14_0_count': server_counts.get('entertainment_14_0_count', 'N/A'),
            'current_time': current_time,
            'visit_count': visit_count,
            'status': 'success',
            'server_status': 'online'
        }
        
        return jsonify(response_data)
    
    except Exception as e:
        logging.error(f"获取最新数据错误: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': '无法获取服务器数据',
            'error': str(e)
        }), 500

def get_server_counts():
    global cached_server_counts, last_update_time
    current_time = time.time()
    
    if cached_server_counts is not None and (current_time - last_update_time) <= 30:
        return cached_server_counts
    
    try:
        # 初始化服务器数据
        counts = {
            'plugin_1_count': 'N/A',
            'entertainment_14_0_count': 'N/A'
        }
        
        # 1. 从蓬莱人形获取插件1服数据
        url1 = "https://scp.manghui.net/list/?serverName=%E8%93%AC%E8%8E%B1%E4%BA%BA%E5%BD%A2"
        response1 = requests.get(url1, timeout=10)
        response1.encoding = 'utf-8'
        soup1 = BeautifulSoup(response1.text, 'html.parser')
        rows1 = soup1.find_all('tr')
        
        for row in rows1:
            columns = row.find_all('td')
            if len(columns) >= 4:
                motd = columns[2].get_text()
                people_count = columns[3].get_text().strip()
                
                if '插件一服' in motd:
                    # 解析格式为"当前人数/最大人数"的字符串
                    if '/' in people_count:
                        current_count = people_count.split('/')[0].strip()
                    else:
                        current_count = people_count
                    counts['plugin_1_count'] = current_count
                    break  # 找到后即停止搜索
        
        # 2. 从凛冬之塔获取凛冬之塔数据
        url2 = "https://scp.manghui.net/list/?serverName=%E5%87%9B%E5%86%AC%E4%B9%8B%E5%A1%94"
        response2 = requests.get(url2, timeout=10)
        response2.encoding = 'utf-8'
        soup2 = BeautifulSoup(response2.text, 'html.parser')
        rows2 = soup2.find_all('tr')
        
        for row in rows2:
            columns = row.find_all('td')
            if len(columns) >= 4:
                motd = columns[2].get_text()
                people_count = columns[3].get_text().strip()
                
                if '凛冬之塔' in motd:
                    # 解析格式为"当前人数/最大人数"的字符串
                    if '/' in people_count:
                        current_count = people_count.split('/')[0].strip()
                    else:
                        current_count = people_count
                    counts['entertainment_14_0_count'] = current_count
                    break  # 找到后即停止搜索

        # 缓存结果
        cached_server_counts = counts
        last_update_time = current_time
        return counts
        
    except Exception as e:
        logging.error(f"爬取服务器数据失败: {str(e)}")
        return cached_server_counts or {
            'plugin_1_count': 'N/A',
            'entertainment_14_0_count': 'N/A'
        }

def get_current_time():
    now = datetime.datetime.now()
    return now.strftime('%H:%M:%S:%f')[:-3]

# ==================== 管理员API ====================
@app.route('/admin/api/blacklist', methods=['GET', 'POST', 'DELETE'])
@auth_required
def manage_blacklist():
    if request.method == 'GET':
        return jsonify({
            'blacklisted_ips': list(blacklisted_ips),
            'count': len(blacklisted_ips)
        })
    
    data = request.get_json()
    ip = data.get('ip')
    
    # 修复正则表达式中的错误
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': '无效的IP地址'}), 400
    
    with lock:
        if request.method == 'POST':
            if ip not in blacklisted_ips:
                blacklisted_ips.add(ip)
                block_ip_windows(ip)
                save_blacklist()
                return jsonify({'success': True, 'message': f'已添加IP {ip}到黑名单'})
            return jsonify({'success': False, 'message': 'IP已在黑名单中'})
        
        if request.method == 'DELETE':
            if ip in blacklisted_ips:
                blacklisted_ips.remove(ip)
                unblock_ip_windows(ip)
                save_blacklist()
                return jsonify({'success': True, 'message': f'已从黑名单移除IP {ip}'})
            return jsonify({'error': 'IP不在黑名单中'}), 404

@app.route('/admin/api/whitelist', methods=['GET', 'POST', 'DELETE'])
@auth_required
def manage_whitelist():
    if request.method == 'GET':
        return jsonify({
            'whitelisted_ips': list(whitelisted_ips),
            'count': len(whitelisted_ips)
        })
    
    data = request.get_json()
    ip = data.get('ip')
    
    # 修复正则表达式中的错误
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': '无效的IP地址'}), 400
    
    with lock:
        if request.method == 'POST':
            if ip not in whitelisted_ips:
                whitelisted_ips.add(ip)
                save_whitelist()
                return jsonify({'success': True, 'message': f'已添加IP {ip}到白名单'})
            return jsonify({'success': False, 'message': 'IP已在白名单中'})
        
        if request.method == 'DELETE':
            if ip in whitelisted_ips:
                whitelisted_ips.remove(ip)
                save_whitelist()
                return jsonify({'success': True, 'message': f'已从白名单移除IP {ip}'})
            return jsonify({'error': 'IP不在白名单中'}), 404

# ==================== 主程序 ====================
if __name__ == '__main__':
    # 初始化加载IP列表和模板
    load_ip_lists()
    
    # 启动信息
    logging.info(f"应用启动 - 封禁IP: {len(blacklisted_ips)}个, 白名单IP: {len(whitelisted_ips)}个")

    # 启动Flask应用
    app.run(
        host='0.0.0.0',
        port=5000,
        threaded=True,
        debug=False
    )
