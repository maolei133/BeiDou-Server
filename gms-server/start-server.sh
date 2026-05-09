#!/usr/bin/env bash
set -euo pipefail

# 北斗服务端 Linux 一体化启动脚本
# 对应 gms-server/start-server.bat：
# 1. 应用 BeiDou_new.jar 更新
# 2. 启动 Docker 化 Loki/Promtail 日志系统
# 3. 启动 BeiDou.jar
# 4. 检测新 jar 后自动重启

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOGGING_SCRIPT="${GMS_LOGGING_SCRIPT:-${REPO_ROOT}/LogSystem/Docker/start-logging.sh}"
JAVA_BIN="${JAVA_BIN:-java}"
OLD_JAR="${OLD_JAR:-BeiDou.jar}"
NEW_JAR="${NEW_JAR:-BeiDou_new.jar}"
JAVA_OPTS="${JAVA_OPTS:--Dspring.config.location=application.yml}"

log() { printf '\033[1;34m[服务端]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

apply_update() {
  if [[ -f "$NEW_JAR" ]]; then
    if [[ -f "$OLD_JAR" ]]; then
      log "删除旧版服务端: $OLD_JAR"
      rm -f "$OLD_JAR"
    fi
    log "检测到新版本，正在应用更新: $NEW_JAR -> $OLD_JAR"
    mv "$NEW_JAR" "$OLD_JAR"
    log "更新完成"
  fi
}

start_logging() {
  log "正在检查并启动日志系统..."
  if [[ -x "$LOGGING_SCRIPT" ]]; then
    "$LOGGING_SCRIPT"
    log "日志系统启动流程已完成"
  elif [[ -f "$LOGGING_SCRIPT" ]]; then
    bash "$LOGGING_SCRIPT"
    log "日志系统启动流程已完成"
  else
    warn "未找到日志启动脚本: $LOGGING_SCRIPT"
  fi
}

start_server_once() {
  [[ -f "$OLD_JAR" ]] || fail "未找到服务端 jar: $(pwd)/$OLD_JAR"
  command -v "$JAVA_BIN" >/dev/null 2>&1 || fail "未找到 Java: $JAVA_BIN"
  log "正在启动游戏服务器..."
  # shellcheck disable=SC2086
  exec "$JAVA_BIN" $JAVA_OPTS -jar "$OLD_JAR"
}

main_loop() {
  cd "$SCRIPT_DIR"
  while true; do
    apply_update
    start_logging
    if [[ "${GMS_SERVER_EXEC_MODE:-exec}" == "exec" ]]; then
      start_server_once
    else
      # 测试/守护场景：子进程退出后可继续判断是否有新 jar
      # shellcheck disable=SC2086
      "$JAVA_BIN" $JAVA_OPTS -jar "$OLD_JAR"
    fi
    if [[ -f "$NEW_JAR" ]]; then
      log "检测到新的更新，将在 15 秒后重启服务器..."
      sleep 15
    else
      break
    fi
  done
}

main_loop "$@"
