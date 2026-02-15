#!/bin/bash
# =================================================================
# 189电信宽带测速工具 (Shell版)
# Version: 1.3.0
# Description:
# =================================================================

# --- 全局配置 ---
THREADS=8
DURATION=10
MODE="all" # 模式: all(全测), down(仅下载), up(仅上传)
IP_FLAG="" # 协议栈标志: 空(自动), -4(IPv4), -6(IPv6)
SELECT_NODES=false
BASE_URL="https://speed.sc.189.cn/user_interface/users"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
REFERER="https://speed.sc.189.cn/"

# 新增全局 CURL 参数控制
# -k: 跳过SSL验证 (Insecure)
# -s: 静默模式 (Silent)
# --connect-timeout: 连接超时设为 3 秒
CURL_FLAGS="-k -s --connect-timeout 3"

# --- 运行时变量 ---
SESSION_TOKEN=""
WORKDIR="/tmp/speedtest_189_$$"
TOKEN_VAL="aaa" # 默认Token，后续尝试动态更新

# --- 终端颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 日志输出 ---
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
    echo "  --select               手动选择节点 (仅test有效)"
    echo "  --help                 显示帮助"
    exit 1
}

# --- 资源清理与信号处理 ---
cleanup_files() {
    # 仅清理当前进程的临时目录
    if [[ -d "$WORKDIR" ]]; then
        rm -rf "$WORKDIR"
    fi
}

handle_sigint() {
    trap '' SIGINT SIGTERM
    echo ""
    log "用户中断操作，正在终止进程并清理资源..." "$RED"
    local pids=$(jobs -p)
    if [ -n "$pids" ]; then
        kill -TERM $pids 2>/dev/null
        wait $pids 2>/dev/null
    fi
    cleanup_files
    exit 130
}

trap handle_sigint SIGINT SIGTERM
trap cleanup_files EXIT

# --- 参数解析 ---
COMMAND="test"
if [[ "$1" == "info" || "$1" == "nodes" || "$1" == "test" ]]; then
    COMMAND="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -4) IP_FLAG="-4"; shift ;;
        -6) IP_FLAG="-6"; shift ;;
        --mode) MODE="$2"; shift; shift ;;
        --duration) DURATION="$2"; shift; shift ;;
        --threads) THREADS="$2"; shift; shift ;;
        --ip)
            # 兼容旧的长参数格式
            case "$2" in
                ipv4|4|-4) IP_FLAG="-4" ;;
                ipv6|6|-6) IP_FLAG="-6" ;;
                *) echo "错误: --ip 参数无效，请使用 ipv4/4 或 ipv6/6"; usage ;;
            esac
            shift; shift ;;
        --select) SELECT_NODES=true; shift ;;
        --help) usage ;;
        *) if [[ "$1" == -* ]]; then echo "未知选项: $1"; usage; fi; shift ;;
    esac
done

# --- 依赖检查 ---
check_deps() {
    for cmd in curl awk grep sed sort head cut tr rm cat mkdir kill date; do
        if ! command -v $cmd &> /dev/null; then
            log "错误: 系统缺少必要命令 '$cmd'，请先安装。" "$RED"
            exit 1
        fi
    done
    mkdir -p "$WORKDIR" || { log "错误: 无法创建临时目录 $WORKDIR" "$RED"; exit 1; }
}

# --- JSON 解析工具 ---
get_json_value() {
    local json="$1"
    local key="$2"
    echo "$json" | tr -d '\n\r' | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

get_json_number() {
    local json="$1"
    local key="$2"
    echo "$json" | tr -d '\n\r' | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p'
}

# --- 核心功能函数 ---

# 进度指示器
spinner() {
    local pid=$1
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        # 兼容 OpenWrt BusyBox，sleep 参数取整数
        sleep 1
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# 用户鉴权
authenticate() {
    if [[ "$COMMAND" == "test" ]]; then log "正在进行鉴权..." "$CYAN"; fi
    
    # 使用全局 CURL_FLAGS
    local resp=$(curl $IP_FLAG $CURL_FLAGS -H "User-Agent: $USER_AGENT" "$BASE_URL/getOnlineIP")
    SESSION_TOKEN=$(get_json_value "$resp" "token")
    
    if [ -n "$SESSION_TOKEN" ]; then
        if [[ "$COMMAND" == "test" ]]; then log "鉴权成功." "$GREEN"; fi
        return 0
    else
        log "鉴权失败 (响应: $resp)" "$RED"
        return 1
    fi
}

# 获取用户信息
get_user_info() {
    local max_retries=3
    local attempt=1
    local success=false

    if [[ "$COMMAND" == "test" ]]; then log "获取用户信息..." "$CYAN"; fi

    while [ $attempt -le $max_retries ]; do
        local resp=$(curl $IP_FLAG $CURL_FLAGS -H "User-Agent: $USER_AGENT" -H "Authorization: $SESSION_TOKEN" "$BASE_URL/getUserInfoByOnlineIP")
        local userNo=$(get_json_value "$resp" "userNo")
        
        if [[ -n "$userNo" ]]; then
            local downBand=$(get_json_number "$resp" "aaaDownBand")
            local upBand=$(get_json_number "$resp" "aaaUpBand")
            
            if [[ -z "$downBand" ]]; then downBand=0; fi
            if [[ -z "$upBand" ]]; then upBand=0; fi
            local down_mbps=$(awk "BEGIN {printf \"%.0f\", $downBand/1024}")
            local up_mbps=$(awk "BEGIN {printf \"%.0f\", $upBand/1024}")
            
            # 获取当前 IP (不进行复杂探测，仅用于显示)
            local current_ip="N/A"
            local ip_probe_url="https://speedtp3.sc.189.cn:8299/ip/ipv4"
            if [[ "$IP_FLAG" == "-6" ]]; then
                ip_probe_url="https://speedtp3.sc.189.cn:8299/ip/ipv6"
            fi
            
            local raw_ip_resp=$(curl $IP_FLAG $CURL_FLAGS --max-time 2 "$ip_probe_url" 2>/dev/null)
            
            # 1. 尝试作为 JSON 提取 "IP" 字段 (针对 {"result":true,"IP":"..."} 格式)
            local extracted_ip=$(get_json_value "$raw_ip_resp" "IP")
            
            if [ -n "$extracted_ip" ]; then
                current_ip="$extracted_ip"
            else
                # 2. 如果 JSON 提取失败，尝试正则提取纯 IP (兜底纯文本响应)
                if [[ "$IP_FLAG" == "-6" ]]; then
                    current_ip=$(echo "$raw_ip_resp" | grep -oE "([a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}" | head -n1)
                else
                    current_ip=$(echo "$raw_ip_resp" | grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | head -n1)
                fi
            fi

            echo "--------------------------------"
            echo -e "用户账号: ${GREEN}${userNo}${NC}"
            echo -e "当前 IP : ${GREEN}${current_ip:-未知}${NC}"
            echo -e "签约带宽: 下行 ${YELLOW}${down_mbps}M${NC} / 上行 ${YELLOW}${up_mbps}M${NC}"
            echo "--------------------------------"
            success=true
            break
        else
            log "获取信息失败，正在重试 ($attempt/$max_retries)..." "$YELLOW"
            ((attempt++))
            sleep 1
        fi
    done

    if [ "$success" = false ]; then
        log "警告: 无法获取完整用户信息，将尝试继续测速。" "$YELLOW"
    fi
}

# 探测测速节点 (统一逻辑)
probe_nodes() {
    log "正在探测测速节点..." "$CYAN"
    
    # 尝试解析动态 Token
    local resp=$(curl $IP_FLAG $CURL_FLAGS -H "User-Agent: $USER_AGENT" -H "Authorization: $SESSION_TOKEN" "$BASE_URL/getDownloadUrl")
    local api_dl_url=$(get_json_value "$resp" "downloadUrl")
    local extracted_token=$(echo "$api_dl_url" | sed -n 's/.*token=\([^&]*\).*/\1/p')
    if [ -n "$extracted_token" ]; then TOKEN_VAL="$extracted_token"; fi

    rm -f "$WORKDIR/nodes.raw"

    # 定义单个节点的探测逻辑
    probe_single_node() {
        local i=$1
        local host="speedtp${i}.sc.189.cn"
        local dl_url="https://${host}:8299/download/1000.data?token=${TOKEN_VAL}"
        local up_url="https://${host}:8299/Upload"
        
        # 优化探测逻辑:
        # 1. 使用 $CURL_FLAGS (-k -s)
        # 2. 弃用 -I (HEAD)，改为 GET 并使用 -r 0-2048 (Range) 请求前 2KB 数据
        #    避免部分节点不支持 HEAD 导致探测失败或延迟虚高
        # 3. -w "%{time_connect}" 仅获取 TCP 握手时间 (纯延迟)，不包含数据传输时间
        #    这能更真实地反映节点物理延迟，而不受下载速度/服务器处理时间影响
        local latency=$(curl $IP_FLAG $CURL_FLAGS -o /dev/null -r 0-2048 -w "%{time_connect}" "$dl_url")
        
        if [ $? -eq 0 ] && [ "$latency" != "0.000000" ]; then
            local ms=$(awk "BEGIN {printf \"%.0f\", $latency * 1000}")
            # 输出格式: 延迟 下载地址 上传地址 节点名称
            echo "$ms $dl_url $up_url speedtp$i" >> "$WORKDIR/nodes.raw"
        fi
    }

    # 并发探测所有预设节点 (1-22)
    for i in {1..22}; do
        probe_single_node $i &
    done
    spinner $!
    wait

    # 检查探测结果
    if [ ! -s "$WORKDIR/nodes.raw" ]; then
        local mode_str=${IP_FLAG:-"Auto"}
        log "错误: 未探测到任何可用节点。请检查网络连接或协议栈设置 (当前模式: $mode_str)。" "$RED"
        exit 1
    fi

    # 对结果按延迟进行排序 (数值升序)
    sort -n "$WORKDIR/nodes.raw" > "$WORKDIR/nodes.sorted"
}

# 优选节点
select_nodes() {
    BEST_DL_URLS=()
    BEST_UP_URLS=()
    SELECTED_INFOS=()
    ALL_NODES=()
    
    # 使用 while read 循环读取，提高兼容性
    if [ -f "$WORKDIR/nodes.sorted" ]; then
        while IFS= read -r line; do
            ALL_NODES+=("$line")
        done < "$WORKDIR/nodes.sorted"
    else
        log "错误: 节点列表文件丢失。" "$RED"
        exit 1
    fi

    if [[ "$SELECT_NODES" == "true" ]]; then
        echo -e "\n${CYAN}=== 可用节点列表 ===${NC}"
        local idx=1
        for line in "${ALL_NODES[@]}"; do
            read -r ms dl up name <<< "$line"
            echo -e "[${idx}] ${GREEN}${ms}ms${NC}\t${name}"
            ((idx++))
        done
        echo -e "\n请输入节点序号 (如 1,3)，输入 'all' 全选，直接回车默认选择前3个:"
        read -r input
        if [[ "$input" == "all" ]]; then
            for line in "${ALL_NODES[@]}"; do
                read -r ms dl up name <<< "$line"
                BEST_DL_URLS+=("$dl")
                BEST_UP_URLS+=("$up")
                SELECTED_INFOS+=("${name}(${ms}ms)")
            done
        elif [[ -n "$input" ]]; then
            IFS=',' read -ra IDX <<< "$input"
            for i in "${IDX[@]}"; do
                local line="${ALL_NODES[$((i-1))]}"
                if [[ -n "$line" ]]; then
                    read -r ms dl up name <<< "$line"
                    BEST_DL_URLS+=("$dl")
                    BEST_UP_URLS+=("$up")
                    SELECTED_INFOS+=("${name}(${ms}ms)")
                fi
            done
        fi
    fi

    # 若未手动选择，默认自动优选前3个低延迟节点
    if [ ${#BEST_DL_URLS[@]} -eq 0 ]; then
        local count=0
        for line in "${ALL_NODES[@]}"; do
            read -r ms dl up name <<< "$line"
            BEST_DL_URLS+=("$dl")
            BEST_UP_URLS+=("$up")
            SELECTED_INFOS+=("${name} [${ms}ms]")
            ((count++))
            if [ $count -ge 3 ]; then break; fi
        done
    fi
    
    echo -e "\n${CYAN}=== 已优选测速节点 ===${NC}"
    for info in "${SELECTED_INFOS[@]}"; do
        echo -e " -> ${GREEN}$info${NC}"
    done
    echo ""
}

# 执行测速任务
run_test() {
    local type=$1
    local title=$2
    # 使用引用传递数组变量名
    local -n urls_ref=$3 
    local urls_count=${#urls_ref[@]}
    
    if [ "$urls_count" -eq 0 ]; then
        log "错误: 未选定有效的测速节点。" "$RED"
        exit 1
    fi

    local test_dir="$WORKDIR/test_$type"
    mkdir -p "$test_dir"
    
    # 生成上传测试数据 (仅生成一次并复用)
    local upload_file="$WORKDIR/upload.bin"
    if [ "$type" == "up" ] && [ ! -f "$upload_file" ]; then
        # 生成 512KB 的随机数据文件
        dd if=/dev/urandom of="$upload_file" bs=1k count=512 2>/dev/null
    fi

    log "开始${title}测试 (时长: ${DURATION}s, 线程: ${THREADS})..." "$CYAN"
    
    local pids=""
    local start_time=$(date +%s)
    local end_time_global=$((start_time + DURATION))

    for ((i=0; i<THREADS; i++)); do
        local idx=$((i % urls_count))
        local url="${urls_ref[$idx]}"
        
        (
            local thread_bytes=0
            
            while [ $(date +%s) -lt $end_time_global ]; do
                local now=$(date +%s)
                local remain=$((end_time_global - now))
                [ $remain -le 0 ] && break
                
                # 应用全局 CURL_FLAGS
                if [ "$type" == "down" ]; then
                    local b=$(curl $IP_FLAG $CURL_FLAGS -o /dev/null -w "%{size_download}" --max-time $remain "$url")
                    thread_bytes=$((thread_bytes + b))
                else
                    # 上传测试: 添加随机参数防止服务端缓存
                    local target="${url}?r=$RANDOM"
                    # 使用 --data-binary 发送二进制数据
                    local b=$(curl $IP_FLAG $CURL_FLAGS -o /dev/null -w "%{size_upload}" --max-time $remain \
                        -X POST -H "Content-Type: application/octet-stream" \
                        --data-binary @"$upload_file" "$target")
                    thread_bytes=$((thread_bytes + b))
                fi
            done
            # 将线程结果写入独立文件，避免竞争
            echo $thread_bytes > "$test_dir/$i.res"
        ) &
        pids="$pids $!"
    done
    
    spinner $!
    wait $pids
    
    local real_end_time=$(date +%s)
    local diff=$((real_end_time - start_time))
    [ $diff -eq 0 ] && diff=1 
    
    local total=0
    # 汇总所有线程的吞吐量
    for f in "$test_dir"/*.res; do
        if [ -f "$f" ]; then
            val=$(cat "$f")
            total=$((total + val))
        fi
    done
    
    # 计算速率: (Total Bytes * 8) / 1024 / 1024 / Time
    local mbps=$(awk "BEGIN {printf \"%.2f\", ($total * 8) / 1048576 / $diff}")
    log "${title}结果: ${mbps} Mbps" "$GREEN"
}

# --- 主程序入口 ---

check_deps

# 处理 'info' 命令
if [[ "$COMMAND" == "info" ]]; then
    authenticate || exit 1
    get_user_info
    exit 0
fi

# 处理 'nodes' 命令
if [[ "$COMMAND" == "nodes" ]]; then
    authenticate || exit 1
    probe_nodes
    echo -e "\n${CYAN}可用节点列表:${NC}"
    awk '{print "延迟: " $1 "ms  \t地址: " $2}' "$WORKDIR/nodes.sorted"
    exit 0
fi

# 处理 'test' 命令 (默认)
if [[ "$COMMAND" == "test" ]]; then
    authenticate || exit 1
    get_user_info
    probe_nodes
    select_nodes
    
    if [[ "$MODE" == "all" || "$MODE" == "down" ]]; then
        run_test "down" "下载" BEST_DL_URLS
    fi
    
    # 任务间隔，缓解网络压力
    if [[ "$MODE" == "all" ]]; then
        sleep 1
    fi
    
    if [[ "$MODE" == "all" || "$MODE" == "up" ]]; then
        run_test "up" "上传" BEST_UP_URLS
    fi
    echo "测速任务完成。"
    exit 0
fi
