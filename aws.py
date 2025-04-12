#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import os
import sys
import json
import logging
import requests
import socket
import threading

# 定义日志格式
level = logging.INFO
logging.basicConfig(
    level=level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 创建默认配置
def create_default_config():
    config_file = "config.json"
    default_config = {
        "global": {
            "round_time": 600,
            "check_method": "remote",  # 可选: "local", "remote"
            "check_server_url": "http://8.130.42.117:5000/check",  # 远程检测服务地址
            "check_attempts": 3,  # 本地检测尝试次数
            "check_timeout": 3,  # 本地检测超时时间（秒）
            "proxy": ""
        },
        "servers": [
            {
                "region": "ap-southeast-1",
                "aws_name": "your-instance-name",
                "ip_name": "your-static-ip-name",
                "port": 443
            }
        ]
    }
    with open(config_file, "w") as f:
        json.dump(default_config, f, indent=4)
    return default_config

# 读取配置文件
def load_config():
    config_file = "config.json"
    try:
        if not os.path.exists(config_file):
            logger.error(f"配置文件 {config_file} 不存在，创建默认配置")
            config = create_default_config()
            logger.error(f"请更新 {config_file} 文件并重启程序")
            sys.exit(1)
        else:
            with open(config_file, "r") as f:
                config = json.load(f)
            
            # 设置代理（如果有）
            proxy_url = config["global"].get("proxy", "")
            if proxy_url:
                os.environ["http_proxy"] = proxy_url
                os.environ["https_proxy"] = proxy_url
                
            return config
                    
    except Exception as e:
        logger.error(f"读取配置错误: {str(e)}")
        sys.exit(1)

# 检查服务器连接状态类
class CheckConnection:
    # 本地TCP连接检测
    @staticmethod
    def local_check(ip, port, timeout=3, attempts=3):
        """
        通过本地Socket尝试连接指定IP和端口
        """
        for attempt in range(1, attempts + 1):
            try:
                logger.debug(f"尝试 {attempt}/{attempts}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    logger.debug(f"成功连接到 {ip}:{port}")
                    return True
                else:
                    logger.debug(f"无法连接到 {ip}:{port}")
            except socket.error as e:
                logger.debug(f"Socket错误: {e}")
            time.sleep(1)  # 等待1秒再尝试
        return False

    # 远程检测服务
    @staticmethod
    def remote_check(ip, port, check_server_url):
        """
        使用远程检测服务检查IP和端口可达性
        """
        try:
            url = check_server_url
            params = {"ip": ip, "port": port}
            logger.debug(f"发送远程检测请求: {url} 参数: {params}")
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get("status") == "success":
                        return data.get("reachable", False)
                    else:
                        logger.error(f"远程检测服务返回错误: {data.get('message', '')}")
                        return False
                except ValueError:
                    # 如果不是JSON格式，尝试解析纯文本响应
                    text = response.text.strip().lower()
                    if text == "true":
                        return True
                    elif text == "false":
                        return False
                    else:
                        logger.error(f"无法解析远程检测服务响应: {response.text}")
                        return False
            else:
                logger.error(f"远程检测服务返回状态码: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"远程检测请求失败: {str(e)}")
            return False

# AWS Lightsail API操作类
class AWSAPI:
    def __init__(self, server_config):
        self.region = server_config["region"]
        self.aws_name = server_config["aws_name"]
        self.ip_name = server_config["ip_name"]
        self.port = server_config["port"]
        
        # 创建实例专用的IP历史记录文件名
        self.ip_history_file = f"ip_history_{self.region}_{self.aws_name}.txt"
    
    # 记录IP地址历史
    def record_ip(self, ip):
        if ip and ip not in self.read_ip():
            with open(self.ip_history_file, "a") as f:
                f.write(ip + "\n")
    
    # 读取IP地址历史
    def read_ip(self):
        ip_list = []
        if not os.path.exists(self.ip_history_file):
            with open(self.ip_history_file, "w") as f:
                return []
        else:
            with open(self.ip_history_file, "r") as f:
                for line in f.readlines():
                    ip_list.append(line.strip())
        return ip_list
    
    # 执行AWS CLI命令
    def aws_cmd(self, cmd):
        try:
            logger.debug(f"执行命令: {cmd}")
            sh = os.popen(cmd)
            result = sh.read()
            return result
        except Exception as e:
            logger.error(f"执行AWS命令失败: {str(e)}")
            raise
    
    # 获取当前静态IP
    def get_ip(self):
        try:
            cmd = f"aws lightsail --region {self.region} get-static-ip --static-ip-name {self.ip_name}"
            result = self.aws_cmd(cmd)
            
            if "ipAddress" not in result:
                return None
                
            ip = result.split("ipAddress")[1].split('"')[2]
            return ip
        except Exception as e:
            logger.error(f"获取IP失败: {str(e)}")
            return None
    
    # 更换IP地址
    def change_ip(self):
        try:
            logger.info(f"开始更换IP地址: {self.aws_name}")
            
            # 获取原IP
            cmd = f"aws lightsail --region {self.region} get-static-ip --static-ip-name {self.ip_name}"
            result = self.aws_cmd(cmd)
            old_ip = result.split("ipAddress")[1].split('"')[2] if "ipAddress" in result else "unknown"
            
            # 解绑IP
            logger.info("解绑IP地址...")
            self.aws_cmd(f"aws lightsail --region {self.region} detach-static-ip --static-ip-name {self.ip_name}")
            
            # 释放IP
            logger.info("释放IP地址...")
            self.aws_cmd(f"aws lightsail --region {self.region} release-static-ip --static-ip-name {self.ip_name}")
            
            # 重新分配IP
            logger.info("分配新IP地址...")
            self.aws_cmd(f"aws lightsail --region {self.region} allocate-static-ip --static-ip-name {self.ip_name}")
            
            # 重新绑定IP
            logger.info("绑定新IP地址...")
            self.aws_cmd(f"aws lightsail --region {self.region} attach-static-ip --static-ip-name {self.ip_name} --instance-name {self.aws_name}")
            
            # 获取新IP
            time.sleep(5)  # 等待IP生效
            cmd = f"aws lightsail --region {self.region} get-static-ip --static-ip-name {self.ip_name}"
            result = self.aws_cmd(cmd)
            new_ip = result.split("ipAddress")[1].split('"')[2] if "ipAddress" in result else "unknown"
            
            # 记录新IP
            self.record_ip(new_ip)
            
            logger.info(f"IP地址已从 {old_ip} 更换为 {new_ip}")
            return old_ip, new_ip
            
        except Exception as e:
            logger.error(f"更换IP失败: {str(e)}")
            raise

# 监控单个服务器
def monitor_server(server_config, global_config):
    try:
        # 初始化AWS API
        aws = AWSAPI(server_config)
        
        # 服务器标识
        server_info = f"{aws.region}/{aws.aws_name}"
        logger.info(f"开始监控服务器: {server_info}")
        
        # 检测方法配置
        check_method = global_config.get("check_method", "local")
        check_server_url = global_config.get("check_server_url", "")
        check_timeout = global_config.get("check_timeout", 3)
        check_attempts = global_config.get("check_attempts", 3)
        
        while True:
            try:
                # 获取当前IP
                ip = aws.get_ip()
                if not ip:
                    logger.warning(f"服务器 {server_info} 未分配IP地址，尝试分配...")
                    try:
                        old_ip, ip = aws.change_ip()
                        logger.info(f"服务器 {server_info} 已分配IP: {ip}")
                    except Exception as e:
                        logger.error(f"分配IP失败: {str(e)}")
                        time.sleep(global_config.get("round_time", 600))
                        continue
                
                # 检查连接状态
                logger.info(f"检查服务器 {server_info} ({ip}:{aws.port}) 连接状态...")
                
                if check_method == "remote" and check_server_url:
                    # 使用远程检测服务
                    logger.info(f"使用远程检测服务: {check_server_url}")
                    reachable = CheckConnection.remote_check(ip, aws.port, check_server_url)
                else:
                    # 使用本地检测
                    logger.info("使用本地检测")
                    reachable = CheckConnection.local_check(ip, aws.port, check_timeout, check_attempts)
                
                if reachable:
                    logger.info(f"服务器 {server_info} ({ip}:{aws.port}) 连接正常")
                else:
                    logger.warning(f"服务器 {server_info} ({ip}:{aws.port}) 连接失败，尝试更换IP...")
                    try:
                        old_ip, new_ip = aws.change_ip()
                        logger.info(f"服务器 {server_info} IP已更换: 旧IP: {old_ip} -> 新IP: {new_ip}")
                    except Exception as e:
                        logger.error(f"服务器 {server_info} 更换IP失败: {str(e)}")
                
                # 等待下一轮检查
                time.sleep(global_config.get("round_time", 600))
                
            except Exception as e:
                logger.error(f"监控服务器 {server_info} 时发生错误: {str(e)}")
                time.sleep(global_config.get("round_time", 600))
                
    except Exception as e:
        logger.error(f"初始化服务器 {server_config['aws_name']} 监控失败: {str(e)}")

# 主程序
if __name__ == "__main__":
    try:
        # 加载配置
        config = load_config()
        global_config = config["global"]
        servers = config["servers"]
        
        # 启动多线程监控
        threads = []
        for server_config in servers:
            thread = threading.Thread(
                target=monitor_server,
                args=(server_config, global_config),
                daemon=True
            )
            threads.append(thread)
            thread.start()
            logger.info(f"已启动服务器 {server_config['aws_name']} 的监控线程")
        
        # 等待所有线程结束（除非手动终止）
        for thread in threads:
            thread.join()
            
    except Exception as e:
        logger.error(f"主程序错误: {str(e)}")
        time.sleep(10)
        sys.exit(1)
