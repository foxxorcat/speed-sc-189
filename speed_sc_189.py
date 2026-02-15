# -*- coding: utf-8 -*-
"""
189电信宽带测速工具
Author: foxxorcat
Version: 1.2.0
Description:
"""

import requests
import time
import random
import threading
import argparse
import sys
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# 尝试导入 rich 库用于增强终端显示效果
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
    from rich.table import Table
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# 禁用不安全请求警告 (针对自签名证书节点)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SocketPatcher:
    """
    网络协议栈补丁管理器
    
    功能:
        通过 Hook socket.getaddrinfo 方法，强制 Python 网络层只使用 IPv4 或 IPv6 协议栈。
        用于在双栈网络环境下强制测试特定协议的连通性和速度。
    """
    def __init__(self, mode):
        self.mode = mode.lower()
        self.original_getaddrinfo = socket.getaddrinfo

    def __enter__(self):
        if self.mode not in ['ipv4', 'ipv6']:
            return
        
        target_family = socket.AF_INET6 if self.mode == 'ipv6' else socket.AF_INET

        def patched_getaddrinfo(*args, **kwargs):
            try:
                # 调用原始解析逻辑
                res = self.original_getaddrinfo(*args, **kwargs)
                # 过滤出符合目标协议族的地址
                filtered = [r for r in res if r[0] == target_family]
                return filtered
            except Exception:
                return []
        
        socket.getaddrinfo = patched_getaddrinfo

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.mode not in ['ipv4', 'ipv6']:
            return
        # 恢复原始 socket 方法
        socket.getaddrinfo = self.original_getaddrinfo

class TelecomSpeedTester:
    """
    电信宽带测速核心类
    """
    def __init__(self, verbose=True, simple_mode=False, ip_mode='auto'):
        self.base_url = "https://speed.sc.189.cn/user_interface/users"
        self.session_token = ""
        self.download_token = ""
        self.user_info = {}
        
        # 节点存储结构: {'download': [NodeObj], 'upload': [NodeObj]}
        self.available_nodes = {'download': [], 'upload': []}
        # 选中的节点索引集合
        self.selected_indices = {'download': set(), 'upload': set()}
        
        self.ipv4_addr = "未检测"
        self.ipv6_addr = "未检测"
        
        self.verbose = verbose
        self.simple_mode = simple_mode
        self.ip_mode = ip_mode
        
        # 初始化 Rich Console (仅在非简易模式且已安装库时启用)
        self.console = Console() if HAS_RICH and not simple_mode else None
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Referer': 'https://speed.sc.189.cn/',
            'Origin': 'https://speed.sc.189.cn'
        }
        
        # 默认测速配置
        self.config = {
            'duration': 10,     # 测速时长(秒)
            'threads': 8,       # 并发线程数
            'unit': 'Mbps',     # 显示单位
            'mode': 'all'       # 测速模式
        }

    def log(self, msg, style="white"):
        """统一日志输出方法"""
        if self.simple_mode:
            return 
            
        if self.console:
            self.console.print(msg, style=style)
        elif self.verbose:
            print(msg)

    def _get_api_headers(self, token=None):
        headers = self.headers.copy()
        if token:
            headers['Authorization'] = token
        return headers

    def detect_ips(self):
        """
        探测当前网络环境的公网 IP 地址 (IPv4/IPv6)
        """
        def parse_ip_resp(resp):
            if not resp.text.strip(): return None
            try:
                data = resp.json()
                return data.get("IP")
            except:
                return resp.text.strip()

        # 检测 IPv4
        try:
            resp4 = requests.get('https://speedtp3.sc.189.cn:8299/ip/ipv4', timeout=3, verify=False)
            self.ipv4_addr = parse_ip_resp(resp4) if resp4.status_code == 200 else "检测失败"
        except: self.ipv4_addr = "检测异常"

        # 检测 IPv6
        try:
            resp6 = requests.get('https://speedtp3.sc.189.cn:8299/ip/ipv6', timeout=3, verify=False)
            self.ipv6_addr = parse_ip_resp(resp6) if resp6.status_code == 200 else "不支持/未连接"
        except: self.ipv6_addr = "不支持/未连接"

    def authenticate(self):
        """
        执行 API 鉴权流程，获取 Session Token
        """
        url = f"{self.base_url}/getOnlineIP"
        try:
            resp = requests.get(url, headers=self.headers, timeout=5)
            res_json = resp.json()
            if res_json.get("code") == 0:
                self.session_token = res_json["data"]["token"]
                return True
        except Exception as e:
            self.log(f"[-] 鉴权请求异常: {e}", style="red")
        return False

    def get_user_info(self):
        """
        获取用户宽带签约信息
        """
        url = f"{self.base_url}/getUserInfoByOnlineIP"
        try:
            resp = requests.get(url, headers=self._get_api_headers(self.session_token), timeout=5)
            res_json = resp.json()
            if res_json.get("code") == 0:
                self.user_info = res_json["data"]
                return True
        except: pass
        return False

    def probe_nodes(self):
        """
        获取并探测测速节点可用性与延迟
        """
        self.available_nodes = {'download': [], 'upload': []}
        
        # 1. 获取官方配置的节点列表
        # 注意: 此处 API 调用使用默认网络栈，避免因强制 IPv6 导致管理接口无法访问
        url = f"{self.base_url}/getDownloadUrl"
        api_nodes_down, api_nodes_up = [], []
        
        try:
            resp = requests.get(url, headers=self._get_api_headers(self.session_token), timeout=5)
            if resp.json().get("code") == 0:
                data = resp.json()["data"]
                # 提取下载鉴权 Token
                raw_token_url = data.get('downloadUrl', '')
                self.download_token = raw_token_url.split('token=')[-1] if 'token=' in raw_token_url else "aaa"
                
                if data.get('bigDownLoadUrl'):
                    for u in data['bigDownLoadUrl'].split('|'):
                        if u.strip(): api_nodes_down.append(u.replace('token=aaa', f'token={self.download_token}'))
                if data.get('bigUpLoadUrl'):
                    for u in data['bigUpLoadUrl'].split('|'):
                        if u.strip(): api_nodes_up.append(u)
        except: pass

        # 2. 构建候选节点集合 (API 返回 + 预设 range 扫描)
        candidate_down = set(api_nodes_down)
        candidate_up = set(api_nodes_up)
        for i in range(1, 23):
            base = f"https://speedtp{i}.sc.189.cn:8299"
            candidate_down.add(f"{base}/download/1000.data?token={self.download_token}")
            candidate_up.add(f"{base}/Upload")

        # 3. 定义探测逻辑
        def probe(url, type_):
            t_start = time.time()
            try:
                # 探测请求受 SocketPatcher 影响，验证指定协议栈的连通性
                if type_ == 'down':
                    r = requests.get(url, stream=True, timeout=2, verify=False)
                    r.close()
                else:
                    r = requests.post(url, data=b'', timeout=2, verify=False)
                
                latency = (time.time() - t_start) * 1000 # ms
                if r.status_code in [200, 204]:
                    node_id = "?"
                    if 'speedtp' in url:
                        node_id = url.split('speedtp')[1].split('.')[0]
                        node_id = f"node{node_id}"
                    else:
                        node_id = url.split('/')[2].split(':')[0]
                        if '[' in node_id: node_id = "IPv6_Node"
                    return {'url': url, 'latency': latency, 'id': node_id}
            except: pass
            return None

        # 4. 执行并发探测
        def run_probe():
            with SocketPatcher(self.ip_mode):
                with ThreadPoolExecutor(max_workers=24) as executor:
                    futures_down = {executor.submit(probe, u, 'down'): u for u in candidate_down}
                    for f in as_completed(futures_down):
                        res = f.result()
                        if res: 
                            self.available_nodes['download'].append(res)
                            if progress: progress.advance(task)
                    
                    futures_up = {executor.submit(probe, u, 'up'): u for u in candidate_up}
                    for f in as_completed(futures_up):
                        res = f.result()
                        if res: 
                            self.available_nodes['upload'].append(res)
                            if progress: progress.advance(task)

        progress = None
        desc_text = f"[cyan]正在探测节点 ({self.ip_mode})..."
        
        if self.console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                transient=True,
                console=self.console
            ) as progress:
                task = progress.add_task(desc_text, total=len(candidate_down) + len(candidate_up))
                run_probe()
        else:
            if not self.simple_mode and self.verbose:
                print(f"正在探测节点延迟 ({self.ip_mode})...")
            run_probe()

        # 5. 按延迟排序
        self.available_nodes['download'].sort(key=lambda x: x['latency'])
        self.available_nodes['upload'].sort(key=lambda x: x['latency'])
        
        # 默认自动选择前 3 个低延迟节点
        self.selected_indices['download'] = set(range(min(3, len(self.available_nodes['download']))))
        self.selected_indices['upload'] = set(range(min(3, len(self.available_nodes['upload']))))
        
        return len(self.available_nodes['download'])

    def select_nodes_interactive(self):
        """
        交互式节点选择功能
        允许用户通过命令行输入序号来指定测试节点
        """
        target_types = []
        if self.config['mode'] in ['all', 'down']:
            target_types.append('download')
        if self.config['mode'] in ['all', 'up']:
            target_types.append('upload')

        for t_type in target_types:
            nodes = self.available_nodes[t_type]
            if not nodes:
                continue

            # 显示节点列表
            title_map = {'download': '下载', 'upload': '上传'}
            if self.console:
                table = Table(title=f"可用{title_map[t_type]}节点列表", box=box.SIMPLE)
                table.add_column("序号", justify="right", style="cyan")
                table.add_column("节点ID", style="bold")
                table.add_column("延迟", justify="right")
                table.add_column("地址", style="dim")
                
                for idx, node in enumerate(nodes):
                    lat_str = f"{node['latency']:.1f}ms"
                    lat_style = "green" if node['latency'] < 50 else "yellow"
                    table.add_row(str(idx + 1), node['id'], f"[{lat_style}]{lat_str}[/]", node['url'].split('/')[2])
                
                self.console.print(table)
                self.console.print(f"[bold]请输入要使用的节点序号 (例如: 1,3)，输入 'all' 全选 (默认前3个):[/]")
            else:
                print(f"\n=== 可用{title_map[t_type]}节点 ===")
                for idx, node in enumerate(nodes):
                    print(f"[{idx+1}] ID:{node['id']} Latency:{node['latency']:.1f}ms Host:{node['url'].split('/')[2]}")
                print("请输入节点序号 (例如: 1,3):")

            # 获取用户输入
            try:
                user_input = input("> ").strip()
                if not user_input:
                    continue # 保持默认
                
                if user_input.lower() == 'all':
                    self.selected_indices[t_type] = set(range(len(nodes)))
                else:
                    indices = set()
                    parts = user_input.replace('，', ',').split(',')
                    for p in parts:
                        try:
                            idx = int(p.strip()) - 1
                            if 0 <= idx < len(nodes):
                                indices.add(idx)
                        except ValueError:
                            pass
                    
                    if indices:
                        self.selected_indices[t_type] = indices
                        self.log(f"[+] 已选择 {len(indices)} 个{title_map[t_type]}节点", style="green")
            except KeyboardInterrupt:
                sys.exit(0)

    def _format_speed(self, bps, unit=None, simple=False):
        u = unit or self.config['unit']
        if simple:
            if u == 'MB/s':
                return f"{bps / 8 / 1024 / 1024:.2f}"
            return f"{bps / 1024 / 1024:.2f}"
            
        if u == 'MB/s':
            return f"{bps / 8 / 1024 / 1024:.2f} MB/s"
        return f"{bps / 1024 / 1024:.2f} Mbps"

    def run_test(self, test_type):
        """
        执行测速核心逻辑
        Returns:
            dict: {'avg': float, 'max': float, 'min': float} 单位 bps
        """
        indices = self.selected_indices[test_type]
        if not indices:
            if self.available_nodes[test_type]:
                # 如果未选中任何节点但有可用节点，尝试兜底
                target_nodes = self.available_nodes[test_type]
            else:
                return {'avg': 0, 'max': 0, 'min': 0}
        else:
            target_nodes = [self.available_nodes[test_type][i] for i in indices if i < len(self.available_nodes[test_type])]
        
        if not target_nodes: return {'avg': 0, 'max': 0, 'min': 0}

        urls = [n['url'] for n in target_nodes]
        
        duration = min(self.config['duration'], 60)
        threads = self.config['threads']
        if test_type == 'upload': threads = max(1, threads // 2)

        stop_event = threading.Event()
        total_bytes = 0
        lock = threading.Lock()
        
        # 准备上传数据 (512KB 随机块)
        upload_block_size = 512 * 1024
        upload_raw_data = random.randbytes(upload_block_size) if test_type == 'upload' else b''

        # 瞬时速度采样容器
        speed_samples = []

        def worker():
            nonlocal total_bytes
            # 在线程内应用协议补丁，确保并发请求也遵循 IP 模式
            with SocketPatcher(self.ip_mode):
                while not stop_event.is_set():
                    url = random.choice(urls)
                    try:
                        if test_type == 'download':
                            with requests.get(url, stream=True, timeout=5, verify=False) as r:
                                for chunk in r.iter_content(chunk_size=65536):
                                    if stop_event.is_set(): break
                                    if chunk:
                                        with lock: total_bytes += len(chunk)
                        else:
                            # 上传: 使用 POST 发送二进制数据
                            target_url = url
                            # 添加随机参数防止缓存
                            sep = '&' if '?' in target_url else '?'
                            target_url += f"{sep}r={random.random()}"
                            
                            requests.post(target_url, data=upload_raw_data, timeout=10, verify=False)
                            with lock: total_bytes += len(upload_raw_data)
                    except: 
                        time.sleep(0.5)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for _ in range(threads): executor.submit(worker)
            
            start_time = time.time()
            title = "Download" if test_type == 'download' else "Upload"
            color = "green" if test_type == 'download' else "blue"
            
            last_sample_time = start_time
            last_sample_bytes = 0

            try:
                # 进度条显示与采样循环
                if self.console:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn(f"[{color}]{{task.description}}"),
                        BarColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        TimeRemainingColumn(),
                        TextColumn(f"[{color}]Rate: {{task.fields[speed]}}"),
                        console=self.console,
                        transient=False
                    ) as progress:
                        task = progress.add_task(title, total=duration, speed="0.00")
                        while not stop_event.is_set():
                            now = time.time()
                            elapsed = now - start_time
                            if elapsed >= duration: break
                            
                            # 采样瞬时速度 (每0.5秒)
                            dt = now - last_sample_time
                            if dt >= 0.5:
                                d_bytes = total_bytes - last_sample_bytes
                                inst_bps = (d_bytes * 8) / dt
                                speed_samples.append(inst_bps)
                                last_sample_time = now
                                last_sample_bytes = total_bytes
                            
                            # 计算累计平均速度用于 UI 显示 (这里仍显示总平均，包含启动时间，避免UI跳变)
                            avg_display = (total_bytes * 8) / elapsed if elapsed > 0 else 0
                            progress.update(task, completed=elapsed, speed=self._format_speed(avg_display))
                            time.sleep(0.1)
                else:
                    while not stop_event.is_set():
                        now = time.time()
                        if now - start_time >= duration: break
                        
                        dt = now - last_sample_time
                        if dt >= 0.5:
                            d_bytes = total_bytes - last_sample_bytes
                            inst_bps = (d_bytes * 8) / dt
                            speed_samples.append(inst_bps)
                            last_sample_time = now
                            last_sample_bytes = total_bytes
                        time.sleep(0.1)

            finally:
                stop_event.set()

        # 统计 Min/Max/Avg
        if not speed_samples:
            # 如果没有采样到数据（例如全部失败），则全部为0或依据总计计算
            final_avg_bps = (total_bytes * 8) / (time.time() - start_time)
            max_bps = final_avg_bps
            min_bps = final_avg_bps
        else:
            max_bps = max(speed_samples)
            
            # 过滤掉 0 值，除非全为 0
            non_zero_samples = [s for s in speed_samples if s > 0]
            
            if non_zero_samples:
                min_bps = min(non_zero_samples)
                # 修复逻辑: 平均速度使用【非零样本的平均值】
                # 这能有效剔除 HTTP 建连阶段的等待时间，避免出现 Avg < Min 的情况
                final_avg_bps = sum(non_zero_samples) / len(non_zero_samples)
            else:
                min_bps = 0
                final_avg_bps = 0
        
        return {
            'avg': final_avg_bps,
            'max': max_bps,
            'min': min_bps
        }

# --- 命令行处理器 ---

def cmd_info(args, tester):
    """处理 info 子命令"""
    tester.detect_ips()
    if tester.authenticate() and tester.get_user_info():
        info = tester.user_info
        
        if tester.console:
            table = Table(title="用户宽带信息", show_header=False, box=box.ROUNDED)
            table.add_row("账号", str(info.get('userNo')))
            table.add_row("IPv4", tester.ipv4_addr)
            table.add_row("IPv6", tester.ipv6_addr)
            table.add_row("签约下行", f"{info.get('aaaDownBand',0)/1024:.0f} Mbps")
            table.add_row("签约上行", f"{info.get('aaaUpBand',0)/1024:.0f} Mbps")
            tester.console.print(table)
        else:
            print(f"User:{info.get('userNo')}")
            print(f"IPv4:{tester.ipv4_addr}")
            print(f"IPv6:{tester.ipv6_addr}")
            print(f"Down:{info.get('aaaDownBand',0)/1024}")
            print(f"Up:{info.get('aaaUpBand',0)/1024}")

def cmd_nodes(args, tester):
    """处理 nodes 子命令"""
    tester.detect_ips()
    tester.authenticate()
    tester.probe_nodes()
    
    down_nodes = tester.available_nodes['download']
    up_nodes = tester.available_nodes['upload']
    
    if tester.console:
        table = Table(title=f"可用节点列表 ({tester.ip_mode})", box=box.SIMPLE)
        table.add_column("Type", style="cyan")
        table.add_column("ID", style="bold")
        table.add_column("Latency", justify="right")
        table.add_column("Host", style="dim")
        
        for n in down_nodes:
            lat_color = "green" if n['latency'] < 50 else "yellow" if n['latency'] < 100 else "red"
            table.add_row("Down", n['id'], f"[{lat_color}]{n['latency']:.1f}ms[/]", n['url'].split('/')[2])
            
        for n in up_nodes:
            lat_color = "green" if n['latency'] < 50 else "yellow" if n['latency'] < 100 else "red"
            table.add_row("Up", n['id'], f"[{lat_color}]{n['latency']:.1f}ms[/]", n['url'].split('/')[2])
            
        tester.console.print(table)
    else:
        for n in down_nodes:
            print(f"Down|{n['id']}|{n['latency']:.2f}|{n['url'].split('/')[2]}")
        for n in up_nodes:
            print(f"Up|{n['id']}|{n['latency']:.2f}|{n['url'].split('/')[2]}")

def cmd_test(args, tester):
    """处理 test 子命令"""
    tester.detect_ips()
    tester.authenticate()
    tester.probe_nodes()
    
    # 交互式节点选择 (如果开启)
    if args.select and not args.simple:
        tester.select_nodes_interactive()
    
    # 应用参数配置
    if args.duration: tester.config['duration'] = args.duration
    if args.threads: tester.config['threads'] = args.threads
    if args.unit: tester.config['unit'] = args.unit
    
    results = {}
    
    # 执行下载测试
    if args.mode in ['all', 'down']:
        if tester.console: tester.console.print(f"[bold]开始下行测试 ({tester.ip_mode})...[/]")
        results['down'] = tester.run_test('download')
    
    # 执行上传测试
    if args.mode in ['all', 'up']:
        if tester.console: tester.console.print(f"[bold]开始上行测试 ({tester.ip_mode})...[/]")
        results['up'] = tester.run_test('upload')

    # 结果输出
    if args.simple:
        # 极简模式：只输出数字 avg (空格分隔)
        out_list = []
        if 'down' in results: out_list.append(tester._format_speed(results['down']['avg'], simple=True))
        if 'up' in results: out_list.append(tester._format_speed(results['up']['avg'], simple=True))
        print(" ".join(out_list))
    elif tester.console:
        # 详细表格
        table = Table(title=f"测速结果 ({tester.ip_mode})", box=box.HEAVY)
        table.add_column("项目", justify="right")
        table.add_column("平均速率", style="bold green")
        table.add_column("峰值速率", style="bold cyan")
        table.add_column("最低速率", style="dim")
        
        if 'down' in results: 
            r = results['down']
            table.add_row("下载", 
                          tester._format_speed(r['avg']),
                          tester._format_speed(r['max']),
                          tester._format_speed(r['min']))
        if 'up' in results: 
            r = results['up']
            table.add_row("上传", 
                          tester._format_speed(r['avg']),
                          tester._format_speed(r['max']),
                          tester._format_speed(r['min']))
        tester.console.print(table)
    else:
        # Bash friendly key=value
        if 'down' in results: 
            r = results['down']
            print(f"Down_Avg={tester._format_speed(r['avg'])}")
            print(f"Down_Max={tester._format_speed(r['max'])}")
            print(f"Down_Min={tester._format_speed(r['min'])}")
        if 'up' in results: 
            r = results['up']
            print(f"Up_Avg={tester._format_speed(r['avg'])}")
            print(f"Up_Max={tester._format_speed(r['max'])}")
            print(f"Up_Min={tester._format_speed(r['min'])}")

def main():
    parser = argparse.ArgumentParser(description="China Telecom (189) Speed Test Tool")
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # 通用参数
    parser.add_argument("--ip", choices=['auto', 'ipv4', 'ipv6'], default='auto', help="强制使用 IPv4 或 IPv6 协议栈")

    # 子命令: test
    p_test = subparsers.add_parser("test", help="开始测速")
    p_test.add_argument("--mode", choices=['all', 'down', 'up'], default='all', help="测速模式")
    p_test.add_argument("--duration", type=int, default=10, help="测试时长(秒)")
    p_test.add_argument("--threads", type=int, default=8, help="并发线程数")
    p_test.add_argument("--unit", choices=['Mbps', 'MB/s'], default='Mbps', help="显示单位")
    p_test.add_argument("--simple", action="store_true", help="脚本模式 (仅输出数字)")
    p_test.add_argument("--select", action="store_true", help="交互式选择测速节点")
    p_test.add_argument("--ip", choices=['auto', 'ipv4', 'ipv6'], default='auto', help="强制协议栈")
    
    # 子命令: info
    p_info = subparsers.add_parser("info", help="显示宽带信息")
    p_info.add_argument("--simple", action="store_true", help="脚本模式")
    
    # 子命令: nodes
    p_nodes = subparsers.add_parser("nodes", help="列出可用节点")
    p_nodes.add_argument("--simple", action="store_true", help="脚本模式")
    p_nodes.add_argument("--ip", choices=['auto', 'ipv4', 'ipv6'], default='auto', help="强制协议栈")

    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    # 实例化测试器
    is_simple = getattr(args, 'simple', False)
    # 获取IP模式 (子命令参数优先)
    ip_mode = getattr(args, 'ip', 'auto')
    
    tester = TelecomSpeedTester(verbose=not is_simple, simple_mode=is_simple, ip_mode=ip_mode)

    if args.command == "test":
        cmd_test(args, tester)
    elif args.command == "info":
        cmd_info(args, tester)
    elif args.command == "nodes":
        cmd_nodes(args, tester)

if __name__ == "__main__":
    main()
