#!/usr/bin/env bash
set -euo pipefail

# 北斗服务端 Linux/Docker 日志系统全自动部署脚本
# 设计目标对齐 Windows/LogSystem/Windows/start-logging.bat：
# - 不写死 /home/edam/... 等机器路径
# - 默认基于“当前执行路径/脚本相对路径”自动识别部署位置
# - 如果当前路径处于 Docker Compose 栈中，自动 patch 当前 compose 并部署 Loki/Promtail 容器
# - 如果不是 Docker Compose 栈，则在 LogSystem/Docker/runtime 下自动生成本地日志 compose 并部署容器
#
# 常用方式：
#   1) Docker 栈目录中执行：/path/to/repo/LogSystem/Docker/start-logging.sh
#   2) gms-server/start-server.sh 自动调用：无需参数，使用仓库相对路径 runtime compose

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CALL_DIR="$(pwd)"

LOKI_IMAGE="${LOKI_IMAGE:-grafana/loki:3.0.0}"
PROMTAIL_IMAGE="${PROMTAIL_IMAGE:-grafana/promtail:3.0.0}"
LOKI_PORT="${LOKI_PORT:-3100}"
PROMTAIL_PORT="${PROMTAIL_PORT:-9080}"
LOKI_SERVICE_NAME="${LOKI_SERVICE_NAME:-loki}"
PROMTAIL_SERVICE_NAME="${PROMTAIL_SERVICE_NAME:-promtail}"
GMS_SERVER_SERVICE_NAME="${GMS_SERVER_SERVICE_NAME:-gms-server}"
LOKI_DATA_VOLUME="${LOKI_DATA_VOLUME:-loki-data}"

log() { printf '\033[1;34m[日志系统]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "缺少命令: $1"
}

find_compose_file() {
  if [[ -n "${COMPOSE_FILE:-}" ]]; then
    [[ -f "$COMPOSE_FILE" ]] && { cd "$(dirname "$COMPOSE_FILE")" && printf '%s/%s\n' "$(pwd)" "$(basename "$COMPOSE_FILE")"; return 0; }
    fail "COMPOSE_FILE 指向的文件不存在: $COMPOSE_FILE"
  fi

  # 优先在调用路径向上查找 compose，避免脚本自身位于仓库 LogSystem/Docker 时误判 runtime compose。
  local dir="$CALL_DIR"
  while [[ "$dir" != "/" ]]; do
    for name in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
      if [[ -f "$dir/$name" ]]; then
        printf '%s/%s\n' "$dir" "$name"
        return 0
      fi
    done
    dir="$(dirname "$dir")"
  done

  # 其次从脚本所在路径向上查找。若只找到 LogSystem/Docker/runtime，它就是脚本自动生成的日志栈，可复用。
  dir="$SCRIPT_DIR"
  while [[ "$dir" != "/" ]]; do
    for name in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
      if [[ -f "$dir/$name" ]]; then
        printf '%s/%s\n' "$dir" "$name"
        return 0
      fi
    done
    dir="$(dirname "$dir")"
  done

  return 1
}

DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1 && sudo -n docker ps >/dev/null 2>&1; then
    DOCKER_CMD="sudo docker"
  fi
fi

compose() {
  if $DOCKER_CMD compose version >/dev/null 2>&1; then
    $DOCKER_CMD compose -f "$COMPOSE_FILE" "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f "$COMPOSE_FILE" "$@"
  else
    fail "未找到 docker compose / docker-compose"
  fi
}

urlencode() {
  python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$1"
}

detect_env_name() {
  local base
  base="$(basename "$STACK_DIR" | tr '[:upper:]' '[:lower:]')"
  if [[ "$base" == *test* || "$base" == *dev* ]]; then
    printf 'test'
  else
    printf 'prod'
  fi
}

write_loki_config() {
  mkdir -p "$CONFIG_DIR"
  if [[ ! -f "$LOKI_CONFIG" || "${FORCE:-0}" == "1" ]]; then
    cat > "$LOKI_CONFIG" <<'YAML'
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  instance_addr: 0.0.0.0
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

limits_config:
  max_entries_limit_per_query: 10000
  retention_period: 168h
  allow_structured_metadata: false

compactor:
  working_directory: /loki/compactor
  compaction_interval: 10m
  retention_enabled: true
  delete_request_store: filesystem
YAML
    log "已写入 Loki 配置: $LOKI_CONFIG"
  else
    log "保留已有 Loki 配置: $LOKI_CONFIG"
  fi
}

write_promtail_config() {
  mkdir -p "$CONFIG_DIR"
  touch "$CONFIG_DIR/promtail-positions.yaml"
  if [[ ! -f "$PROMTAIL_CONFIG" || "${FORCE:-0}" == "1" ]]; then
    cat > "$PROMTAIL_CONFIG" <<YAML
server:
  http_listen_port: ${PROMTAIL_PORT}
  grpc_listen_port: 0

positions:
  filename: /tmp/promtail-positions.yaml

clients:
  - url: http://${LOKI_SERVICE_NAME}:3100/loki/api/v1/push

scrape_configs:
  - job_name: gms-audit
    static_configs:
      - targets:
          - localhost
        labels:
          job: gms-audit
          app: gms-server
          env: ${GMS_ENV}
          __path__: /app/logs/audit/*.json
    pipeline_stages:
      - json:
          expressions:
            ts: ts
            mod: mod
            act: act
            msg: msg
            eventType: eventType
            sampledAt: sampledAt
            sampledAtIso: sampledAtIso
            systemCpuLoad: systemCpuLoad
            processCpuLoad: processCpuLoad
            systemMemoryUsage: systemMemoryUsage
            jvmHeapUsage: jvmHeapUsage
            networkRxBytesPerSecond: networkRxBytesPerSecond
            networkTxBytesPerSecond: networkTxBytesPerSecond
            diskReadBytesPerSecond: diskReadBytesPerSecond
            diskWriteBytesPerSecond: diskWriteBytesPerSecond
            cpuAnomaly: cpuAnomaly
            cpuAnomalyLevel: cpuAnomalyLevel
      - labels:
          mod:
          act:
          eventType:
          cpuAnomaly:
          cpuAnomalyLevel:
      - timestamp:
          source: ts
          format: UnixMs

  - job_name: gms-server
    static_configs:
      - targets:
          - localhost
        labels:
          job: gms-server
          app: gms-server
          env: ${GMS_ENV}
          __path__: /app/logs/*.log
    pipeline_stages:
      - regex:
          expression: '^(?P<time>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}) \\[(?P<level>\\w+)\\s*\\] ==> (?P<msg>.*)$'
      - labels:
          level:
      - timestamp:
          source: time
          format: '2006-01-02 15:04:05.000'
          location: Asia/Shanghai

  - job_name: gms-error
    static_configs:
      - targets:
          - localhost
        labels:
          job: gms-error
          app: gms-server
          env: ${GMS_ENV}
          __path__: /app/logs/error/*.log
    pipeline_stages:
      - multiline:
          firstline: '^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}'
          max_wait_time: 3s
      - regex:
          expression: '^(?P<time>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}) \\[(?P<thread>.*?)\\] (?P<level>\\w+)\\s+(?P<logger>.*?) - (?P<msg>.*)$'
      - labels:
          level:
          logger:
      - timestamp:
          source: time
          format: '2006-01-02 15:04:05.000'
          location: Asia/Shanghai
YAML
    log "已写入 Promtail 配置: $PROMTAIL_CONFIG"
  else
    log "保留已有 Promtail 配置: $PROMTAIL_CONFIG"
  fi
}

create_runtime_compose() {
  STACK_DIR="${SCRIPT_DIR}/runtime"
  COMPOSE_FILE="${STACK_DIR}/docker-compose.yml"
  CONFIG_DIR="${STACK_DIR}/docker"
  LOKI_CONFIG="${CONFIG_DIR}/loki-config.yaml"
  PROMTAIL_CONFIG="${CONFIG_DIR}/promtail-config.yml"
  GMS_ENV="${GMS_ENV:-$(detect_env_name)}"
  mkdir -p "$STACK_DIR" "$REPO_ROOT/gms-server/logs/audit" "$REPO_ROOT/gms-server/logs/error"
  write_loki_config
  write_promtail_config
  cat > "$COMPOSE_FILE" <<YAML
services:
  ${LOKI_SERVICE_NAME}:
    image: ${LOKI_IMAGE}
    container_name: gms-loki
    restart: unless-stopped
    command: -config.file=/etc/loki/local-config.yaml
    ports:
      - "${LOKI_PORT}:3100"
    volumes:
      - ./docker/loki-config.yaml:/etc/loki/local-config.yaml:ro
      - ${LOKI_DATA_VOLUME}:/loki
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:3100/ready >/dev/null 2>&1 || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 30

  ${PROMTAIL_SERVICE_NAME}:
    image: ${PROMTAIL_IMAGE}
    container_name: gms-promtail
    restart: unless-stopped
    command: -config.file=/etc/promtail/config.yml
    depends_on:
      ${LOKI_SERVICE_NAME}:
        condition: service_started
    ports:
      - "${PROMTAIL_PORT}:9080"
    volumes:
      - ./docker/promtail-config.yml:/etc/promtail/config.yml:ro
      - ./docker/promtail-positions.yaml:/tmp/promtail-positions.yaml
      - ../../gms-server/logs:/app/logs:ro

volumes:
  ${LOKI_DATA_VOLUME}:
YAML
  log "未发现当前路径 Docker Compose 栈，已创建仓库相对 runtime compose: $COMPOSE_FILE"
}

patch_compose() {
  [[ -f "$COMPOSE_FILE" ]] || fail "未找到 compose 文件: $COMPOSE_FILE"
  python3 - "$COMPOSE_FILE" "$LOKI_IMAGE" "$PROMTAIL_IMAGE" "$LOKI_PORT" "$PROMTAIL_PORT" "$LOKI_DATA_VOLUME" "$LOKI_SERVICE_NAME" "$PROMTAIL_SERVICE_NAME" "$GMS_SERVER_SERVICE_NAME" <<'PY'
from pathlib import Path
import re, sys
path=Path(sys.argv[1])
loki_image,promtail_image,loki_port,promtail_port,loki_data_volume,loki_service,promtail_service,gms_service=sys.argv[2:10]
s=path.read_text()

# 自动识别 gms-server 的 /app/logs 挂载源；默认保持 server-logs volume。
server_log_source='server-logs'
m=re.search(r'\n  '+re.escape(gms_service)+r':\n(?P<body>.*?)(?=\n  [A-Za-z0-9_.-]+:\n|\nvolumes:\n|\Z)', s, re.S)
if m:
    for line in m.group('body').splitlines():
        item=line.strip().strip('"\'')
        if ':/app/logs' in item:
            server_log_source=item.split(':/app/logs',1)[0].strip().lstrip('-').strip().strip('"\'')
            break

# 若之前脚本写入了绝对配置路径，归一化为相对当前 compose 的 ./docker。
s=re.sub(r'-\s+[^\n]*?/docker/loki-config\.yaml:/etc/loki/local-config\.yaml:ro', '- ./docker/loki-config.yaml:/etc/loki/local-config.yaml:ro', s)
s=re.sub(r'-\s+[^\n]*?/docker/promtail-config\.ya?ml:/etc/promtail/config\.yml:ro', '- ./docker/promtail-config.yml:/etc/promtail/config.yml:ro', s)
s=re.sub(r'(- ./docker/promtail-config\.yml:/etc/promtail/config\.yml:ro)(?!\n      - ./docker/promtail-positions\.yaml:/tmp/promtail-positions\.yaml)', r'\1\n      - ./docker/promtail-positions.yaml:/tmp/promtail-positions.yaml', s)

if f"  {loki_service}:\n" not in s:
    block=f'''services:\n  {loki_service}:\n    image: {loki_image}\n    container_name: gms-loki\n    restart: unless-stopped\n    command: -config.file=/etc/loki/local-config.yaml\n    ports:\n      - "{loki_port}:3100"\n    volumes:\n      - ./docker/loki-config.yaml:/etc/loki/local-config.yaml:ro\n      - {loki_data_volume}:/loki\n    healthcheck:\n      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:3100/ready >/dev/null 2>&1 || exit 1"]\n      interval: 10s\n      timeout: 5s\n      retries: 30\n\n  {promtail_service}:\n    image: {promtail_image}\n    container_name: gms-promtail\n    restart: unless-stopped\n    command: -config.file=/etc/promtail/config.yml\n    depends_on:\n      {loki_service}:\n        condition: service_started\n    ports:\n      - "{promtail_port}:9080"\n    volumes:\n      - ./docker/promtail-config.yml:/etc/promtail/config.yml:ro\n      - ./docker/promtail-positions.yaml:/tmp/promtail-positions.yaml\n      - {server_log_source}:/app/logs:ro\n\n'''
    s=s.replace('services:\n', block, 1)
elif f'{server_log_source}:/app/logs:ro' not in s:
    s=re.sub(r'(\n  '+re.escape(promtail_service)+r':\n.*?volumes:\n(?:\n      - .*)*)', r'\1\n      - '+server_log_source+':/app/logs:ro', s, count=1, flags=re.S)

# 确保 gms-server 有 Loki 和 Promtail 地址环境变量。
if m and ('GMS_LOG_LOKI_URL:' not in s or 'GMS_LOG_PROMTAIL_URL:' not in s):
    service_start=m.start('body')
    next_service=re.search(r'\n  [A-Za-z0-9_.-]+:\n|\nvolumes:\n|\Z', s[service_start:], re.S)
    service_end=service_start + (next_service.start() if next_service else len(s)-service_start)
    body=s[service_start:service_end]
    body_lines=body.splitlines()
    env_idx=next((i for i, line in enumerate(body_lines) if line.strip() == 'environment:'), -1)
    if env_idx >= 0:
        insert_idx=env_idx + 1
        while insert_idx < len(body_lines) and body_lines[insert_idx].startswith('      '):
            insert_idx += 1
        additions=[]
        if 'GMS_LOG_LOKI_URL:' not in body:
            additions.append(f'      GMS_LOG_LOKI_URL: http://{loki_service}:3100')
        if 'GMS_LOG_PROMTAIL_URL:' not in body:
            additions.append(f'      GMS_LOG_PROMTAIL_URL: http://{promtail_service}:9080')
        if 'GMS_LOG_CONFIG_DIR:' not in body:
            additions.append('      GMS_LOG_CONFIG_DIR: /app/log-config')
        if 'GMS_LOG_PROMTAIL_POSITIONS_FILE:' not in body:
            additions.append('      GMS_LOG_PROMTAIL_POSITIONS_FILE: /app/log-config/promtail-positions.yaml')
        body_lines[insert_idx:insert_idx]=additions
        new_body='\n'.join(body_lines)
        s=s[:service_start]+new_body+s[service_end:]

# 确保 gms-server 有日志配置目录环境变量，即使 Loki/Promtail URL 已经存在。
service_match=re.search(r'\n  '+re.escape(gms_service)+r':\n(?P<body>.*?)(?=\n  [A-Za-z0-9_.-]+:\n|\nvolumes:\n|\Z)', s, re.S)
if service_match and ('GMS_LOG_CONFIG_DIR:' not in service_match.group('body') or 'GMS_LOG_PROMTAIL_POSITIONS_FILE:' not in service_match.group('body')):
    service_start=service_match.start('body')
    service_end=service_match.end('body')
    body=s[service_start:service_end]
    body_lines=body.splitlines()
    env_idx=next((i for i, line in enumerate(body_lines) if line.strip() == 'environment:'), -1)
    if env_idx >= 0:
        insert_idx=env_idx + 1
        while insert_idx < len(body_lines) and body_lines[insert_idx].startswith('      '):
            insert_idx += 1
        additions=[]
        if 'GMS_LOG_CONFIG_DIR:' not in body:
            additions.append('      GMS_LOG_CONFIG_DIR: /app/log-config')
        if 'GMS_LOG_PROMTAIL_POSITIONS_FILE:' not in body:
            additions.append('      GMS_LOG_PROMTAIL_POSITIONS_FILE: /app/log-config/promtail-positions.yaml')
        body_lines[insert_idx:insert_idx]=additions
        new_body='\n'.join(body_lines)
        s=s[:service_start]+new_body+s[service_end:]

# 确保 gms-server 可读写当前 compose 的日志配置目录，并允许后端通过 Docker socket 控制 Loki/Promtail。
service_match=re.search(r'\n  '+re.escape(gms_service)+r':\n(?P<body>.*?)(?=\n  [A-Za-z0-9_.-]+:\n|\nvolumes:\n|\Z)', s, re.S)
if service_match and ('./docker:/app/log-config' not in service_match.group('body') or '/var/run/docker.sock:/var/run/docker.sock' not in service_match.group('body')):
    service_start=service_match.start('body')
    service_end=service_match.end('body')
    body=s[service_start:service_end]
    body_lines=body.splitlines()
    volumes_idx=next((i for i, line in enumerate(body_lines) if line.strip() == 'volumes:'), -1)
    if volumes_idx >= 0:
        insert_idx=volumes_idx + 1
        while insert_idx < len(body_lines) and body_lines[insert_idx].startswith('      '):
            insert_idx += 1
        additions=[]
        if './docker:/app/log-config' not in body:
            additions.append('      - ./docker:/app/log-config')
        if '/var/run/docker.sock:/var/run/docker.sock' not in body:
            additions.append('      - /var/run/docker.sock:/var/run/docker.sock')
        body_lines[insert_idx:insert_idx]=additions
        new_body='\n'.join(body_lines)
        s=s[:service_start]+new_body+s[service_end:]

# 确保 volumes 有 loki-data；如果 gms-server 没有 /app/logs，则也补 server-logs volume 和挂载。
if 'volumes:\n' not in s:
    s=s.rstrip()+"\n\nvolumes:\n"
if f'  {loki_data_volume}:\n' not in s:
    s=s.rstrip()+f'\n  {loki_data_volume}:\n'
if server_log_source == 'server-logs' and '  server-logs:\n' not in s:
    s=s.rstrip()+"\n  server-logs:\n"

path.write_text(s)
print('patched', path, 'server_log_source=', server_log_source)
PY
}

wait_loki() {
  log "等待 Loki 就绪..."
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 3 "http://127.0.0.1:${LOKI_PORT}/ready" >/dev/null 2>&1; then
      log "Loki 已就绪"
      return 0
    fi
    sleep 2
  done
  compose logs --tail=120 "$LOKI_SERVICE_NAME" || true
  fail "Loki 未能在预期时间内就绪"
}

verify_query() {
  log "验证 Promtail 推送和 Loki 查询..."
  local query='{job="gms-audit"}'
  local encoded
  encoded="$(urlencode "$query")"
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 5 "http://127.0.0.1:${LOKI_PORT}/loki/api/v1/query_range?query=${encoded}&limit=1" >/tmp/gms-loki-query.json 2>/dev/null; then
      if python3 - <<'PY'
import json
from pathlib import Path
p=Path('/tmp/gms-loki-query.json')
data=json.loads(p.read_text())
print('streams', len(data.get('data',{}).get('result',[])))
PY
      then
        log "Loki 查询接口正常"
        return 0
      fi
    fi
    sleep 2
  done
  warn "Loki 查询接口可访问但暂未查到 gms-audit 日志；如果服务端刚启动或暂无 audit 日志，这是可接受的。"
}

main() {
  require_cmd docker
  require_cmd python3
  require_cmd curl

  if detected="$(find_compose_file)"; then
    COMPOSE_FILE="$detected"
    STACK_DIR="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)"
    CONFIG_DIR="${STACK_DIR}/docker"
    LOKI_CONFIG="${CONFIG_DIR}/loki-config.yaml"
    PROMTAIL_CONFIG="${CONFIG_DIR}/promtail-config.yml"
    GMS_ENV="${GMS_ENV:-$(detect_env_name)}"
    log "识别到当前 Docker Compose 栈: $COMPOSE_FILE"
    write_loki_config
    write_promtail_config
    patch_compose
  else
    create_runtime_compose
  fi

  log "启动 Loki/Promtail 容器..."
  compose up -d "$LOKI_SERVICE_NAME" "$PROMTAIL_SERVICE_NAME"
  wait_loki
  verify_query
  log "日志系统部署完成。Compose: $COMPOSE_FILE"
}

main "$@"
