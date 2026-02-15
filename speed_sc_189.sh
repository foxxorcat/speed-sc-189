#!/bin/bash
# =================================================================
# 189电信宽带测速工具 (Shell版)
# Version: 1.2.0
# Description: 
# =================================================================

# 全局配置
THREADS=8
DURATION=10
MODE="all" # all, down, up
IP_FLAG="" # 空(auto), -4, -6
SELECT_NODES=false
BASE_URL="https://speed.sc.189.cn/user_interface/users"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
REFERER="https://speed.sc.189.cn/"

# 全局变量
SESSION_TOKEN=""
ONLINE_IP="" # 存储鉴权时获取的IP

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log() {
    echo -e "${2}${1}${NC}"
}

# 帮助信息
usage() {
    echo "用法: $0 [命令] [选项]"
    echo "命令:"
    echo "  test    开始测速 (默认)"
    echo "  info    仅显示用户信息"
    echo "  nodes   列出所有可用节点"
    echo ""
    echo "选项:"
    echo "  --mode [all|down|up]   测速模式 (仅test有效)"
    echo "  --duration [秒]        测速时长 (默认: 10)"
    echo "  --threads [数量]       并发线程数 (默认: 8)"
    echo "  --ip [auto|ipv4|ipv6]  强制协议栈"
    echo "  --select               交互式手动选择节点 (仅test有效)"
    echo "  --help                 显示帮助"
    exit 1
}

# --- 参数解析逻辑 ---
COMMAND="test"
if [[ "$1" == "info" || "$1" == "nodes" || "$1" == "test" ]]; then
    COMMAND="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --mode) MODE="$2"; shift; shift ;;
        --duration) DURATION="$2"; shift; shift ;;
        --threads) THREADS="$2"; shift; shift ;;
        --ip)
            if [[ "$2" == "ipv4" ]]; then IP_FLAG="-4"; fi
            if [[ "$2" == "ipv6" ]]; then IP_FLAG="-6"; fi
            shift; shift ;;
        --select) SELECT_NODES=true; shift ;;
        --help) usage ;;
        *) if [[ "$1" == -* ]]; then echo "未知选项: $1"; usage; fi; shift ;;
    esac
done

# 检查依赖
check_deps() {
    for cmd in curl awk grep sed sort head cut; do
        if ! command -v $cmd &> /dev/null; then
            log "错误: 未找到必要命令 '$cmd'，请先安装。" "$RED"
            exit 1
        fi
    done
}

# --- JSON 提取工具函数 ---
get_json_value() {
    local json="$1"
    local key="$2"
    # 使用 awk 以 "key": 为分隔符，兼容空格
    # 示例: "ip" : "1.2.3.4" -> 分割后取第二部分，再以双引号分割取值
    echo "$json" | awk -F"\"$key\"[[:space:]]*:[[:space:]]*\"" '{print $2}' | awk -F"\"" '{print $1}'
}

get_json_number() {
    local json="$1"
    local key="$2"
    # 提取数字，处理结尾的逗号或大括号
    echo "$json" | awk -F"\"$key\"[[:space:]]*:[[:space:]]*" '{print $2}' | awk -F"[,}]" '{print $1}' | tr -d ' '
}

# 旋转动画
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# 1. 鉴权
authenticate() {
    if [[ "$COMMAND" == "test" ]]; then log "正在进行鉴权..." "$CYAN"; fi
    
    local resp=$(curl -s $IP_FLAG -H "User-Agent: $USER_AGENT" "$BASE_URL/getOnlineIP" --connect-timeout 5)
    SESSION_TOKEN=$(get_json_value "$resp" "token")
    ONLINE_IP=$(get_json_value "$resp" "ip") # 尝试在此处获取 IP
    
    if [ -n "$SESSION_TOKEN" ]; then
        if [[ "$COMMAND" == "test" ]]; then log "鉴权成功." "$GREEN"; fi
        return 0
    else
        log "鉴权失败，服务器响应: $resp" "$RED"
        return 1
    fi
}

# 2. 获取并显示用户信息
get_user_info() {
    if [[ "$COMMAND" == "test" ]]; then log "获取用户信息..." "$CYAN"; fi
    
    local resp=$(curl -s $IP_FLAG -H "User-Agent: $USER_AGENT" -H "Authorization: $SESSION_TOKEN" "$BASE_URL/getUserInfoByOnlineIP")
    
    local userNo=$(get_json_value "$resp" "userNo")
    local downBand=$(get_json_number "$resp" "aaaDownBand")
    local upBand=$(get_json_number "$resp" "aaaUpBand")
    
    # 1. 优先使用 authenticate 阶段从 getOnlineIP 获取到的 IP
    local my_ip="$ONLINE_IP"
    
    # 2. 如果为空，尝试请求 ip 接口
    if [ -z "$my_ip" ]; then
        # 尝试 IPv4
        local ip_resp=$(curl -s $IP_FLAG -H "User-Agent: $USER_AGENT" https://speedtp3.sc.189.cn:8299/ip/ipv4 --connect-timeout 2)
        # 尝试解析 JSON key "IP" (注意大小写)
        my_ip=$(get_json_value "$ip_resp" "IP")
        
        # 如果解析失败，检查是否为纯文本 IP
        if [ -z "$my_ip" ] && [[ -n "$ip_resp" ]]; then
             # 简单过滤，防止输出 HTML 错误页
             if [[ "$ip_resp" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                my_ip=$(echo "$ip_resp" | tr -d ' \n\r')
             fi
        fi
        
        # 尝试 IPv6
        if [ -z "$my_ip" ]; then
            ip_resp=$(curl -s $IP_FLAG -H "User-Agent: $USER_AGENT" https://speedtp3.sc.189.cn:8299/ip/ipv6 --connect-timeout 2)
            my_ip=$(get_json_value "$ip_resp" "IP")
            if [ -z "$my_ip" ] && [[ -n "$ip_resp" ]]; then
                 if [[ "$ip_resp" =~ : ]]; then
                    my_ip=$(echo "$ip_resp" | tr -d ' \n\r')
                 fi
            fi
        fi
    fi
    
    if [[ -z "$downBand" ]]; then downBand=0; fi
    if [[ -z "$upBand" ]]; then upBand=0; fi

    local down_mbps=$(awk "BEGIN {printf \"%.0f\", $downBand/1024}")
    local up_mbps=$(awk "BEGIN {printf \"%.0f\", $upBand/1024}")
    
    echo "--------------------------------"
    echo -e "用户账号: ${GREEN}$userNo${NC}"
    echo -e "当前 IP : ${GREEN}$my_ip${NC}"
    echo -e "签约带宽: 下行 ${YELLOW}${down_mbps}M${NC} / 上行 ${YELLOW}${up_mbps}M${NC}"
    echo "--------------------------------"
}

# 3. 探测节点
probe_nodes() {
    log "正在探测测速节点..." "$CYAN"
    
    local resp=$(curl -s $IP_FLAG -H "User-Agent: $USER_AGENT" -H "Authorization: $SESSION_TOKEN" "$BASE_URL/getDownloadUrl")
    local dl_url=$(get_json_value "$resp" "downloadUrl")
    
    # 使用 grep 提取 token，兼容性更好
    DOWNLOAD_TOKEN=$(echo "$dl_url" | grep -o "token=[^&]*" | cut -d= -f2)
    if [ -z "$DOWNLOAD_TOKEN" ]; then DOWNLOAD_TOKEN="aaa"; fi

    > /tmp/189_nodes.txt
    
    probe_single() {
        local i=$1
        local host="speedtp${i}.sc.189.cn"
        local url="https://${host}:8299/download/1000.data?token=${DOWNLOAD_TOKEN}"
        local latency=$(curl $IP_FLAG -s -o /dev/null -I -w "%{time_connect}" --connect-timeout 1.5 "$url")
        
        if [ $? -eq 0 ] && [ "$latency" != "0.000000" ]; then
            local ms=$(awk "BEGIN {printf \"%.0f\", $latency * 1000}")
            echo "$ms $url https://${host}:8299/Upload speedtp$i" >> /tmp/189_nodes.txt
        fi
    }

    for i in {1..22}; do
        probe_single $i &
    done
    
    spinner $!
    wait

    if [ ! -s /tmp/189_nodes.txt ]; then
        log "未探测到可用节点，请检查网络。" "$RED"
        exit 1
    fi

    sort -n /tmp/189_nodes.txt -o /tmp/189_nodes.sorted
}

# 4. 选择节点
select_nodes() {
    BEST_DL_URLS=()
    BEST_UP_URLS=()

    mapfile -t ALL_NODES < /tmp/189_nodes.sorted

    if [[ "$SELECT_NODES" == "true" ]]; then
        echo -e "\n${CYAN}=== 可用节点列表 ===${NC}"
        local idx=1
        for line in "${ALL_NODES[@]}"; do
            read -r ms dl up name <<< "$line"
            echo -e "[${idx}] ${GREEN}${ms}ms${NC}\t${name}\t(${dl})"
            ((idx++))
        done
        
        echo -e "\n请输入要使用的节点序号 (例如 1,3)，输入 all 全选，直接回车默认前3个:"
        read -r user_input
        
        if [[ "$user_input" == "all" ]]; then
             for line in "${ALL_NODES[@]}"; do
                read -r ms dl up name <<< "$line"
                BEST_DL_URLS+=("$dl")
                BEST_UP_URLS+=("$up")
            done
        elif [[ -n "$user_input" ]]; then
            IFS=',' read -ra ADDR <<< "$user_input"
            for i in "${ADDR[@]}"; do
                local line="${ALL_NODES[$((i-1))]}"
                if [[ -n "$line" ]]; then
                    read -r ms dl up name <<< "$line"
                    BEST_DL_URLS+=("$dl")
                    BEST_UP_URLS+=("$up")
                fi
            done
        fi
    fi

    if [ ${#BEST_DL_URLS[@]} -eq 0 ]; then
        local count=0
        for line in "${ALL_NODES[@]}"; do
            read -r ms dl up name <<< "$line"
            BEST_DL_URLS+=("$dl")
            BEST_UP_URLS+=("$up")
            ((count++))
            if [ $count -ge 3 ]; then break; fi
        done
        log "已自动优选 ${#BEST_DL_URLS[@]} 个低延迟节点" "$GREEN"
    else
        log "已手动选择 ${#BEST_DL_URLS[@]} 个节点" "$GREEN"
    fi
}

# 5. 执行测速
run_test() {
    local type=$1
    local title=$2
    local urls=("${!3}")
    local tmp_dir=$(mktemp -d)
    
    log "开始${title}测试 (时长: ${DURATION}s, 线程: ${THREADS})..." "$CYAN"
    
    if [ "$type" == "up" ]; then
        dd if=/dev/urandom of="$tmp_dir/upload.dat" bs=1M count=64 status=none
    fi

    local pids=""
    local start_time=$(date +%s.%N)
    
    for ((i=0; i<THREADS; i++)); do
        local node_idx=$((i % ${#urls[@]}))
        local url="${urls[$node_idx]}"
        
        (
            local thread_bytes=0
            local end_time=$(awk "BEGIN {print $(date +%s) + $DURATION}")
            
            while [ $(date +%s) -lt $end_time ]; do
                local current_time=$(date +%s)
                local remain=$((end_time - current_time))
                if [ $remain -le 0 ]; then break; fi
                
                local r=$RANDOM
                
                if [ "$type" == "down" ]; then
                    local bytes=$(curl $IP_FLAG -k -s -o /dev/null -w "%{size_download}" \
                        --max-time $remain \
                        -H "User-Agent: $USER_AGENT" \
                        -H "Referer: $REFERER" \
                        "$url")
                    thread_bytes=$((thread_bytes + bytes))
                else
                    # POST 上传修复
                    local target_url="${url}?r=${r}"
                    local bytes=$(curl $IP_FLAG -k -s -o /dev/null -w "%{size_upload}" \
                        --max-time $remain \
                        -X POST \
                        -H "User-Agent: $USER_AGENT" \
                        -H "Referer: $REFERER" \
                        -H "Content-Type: application/octet-stream" \
                        --data-binary @"$tmp_dir/upload.dat" \
                        "$target_url")
                    thread_bytes=$((thread_bytes + bytes))
                fi
            done
            echo $thread_bytes > "$tmp_dir/thread_${i}.res"
        ) &
        pids="$pids $!"
    done
    
    spinner $!
    wait $pids
    
    local end_time=$(date +%s.%N)
    local actual_duration=$(awk "BEGIN {print $end_time - $start_time}")
    
    local total_bytes=0
    for f in "$tmp_dir"/*.res; do
        if [ -f "$f" ]; then
            local b=$(cat "$f")
            total_bytes=$((total_bytes + b))
        fi
    done
    
    local speed_mbps=$(awk "BEGIN {printf \"%.2f\", ($total_bytes * 8) / (1024 * 1024) / $actual_duration}")
    
    log "${title}结果: ${speed_mbps} Mbps" "$GREEN"
    rm -rf "$tmp_dir"
}

# --- 主逻辑路由 ---

check_deps

if [[ "$COMMAND" == "info" ]]; then
    authenticate || exit 1
    get_user_info
    exit 0
fi

if [[ "$COMMAND" == "nodes" ]]; then
    authenticate || exit 1
    probe_nodes
    echo -e "\n${CYAN}可用节点列表:${NC}"
    cat /tmp/189_nodes.sorted | awk '{print "延迟: " $1 "ms  \tID: " $4 "\t地址: " $2}'
    exit 0
fi

if [[ "$COMMAND" == "test" ]]; then
    authenticate || exit 1
    get_user_info
    probe_nodes
    select_nodes
    
    if [[ "$MODE" == "all" || "$MODE" == "down" ]]; then
        run_test "down" "下载" BEST_DL_URLS[@]
    fi

    if [[ "$MODE" == "all" || "$MODE" == "up" ]]; then
        run_test "up" "上传" BEST_UP_URLS[@]
    fi
    
    echo "测速完成。"
    exit 0
fi

usage
