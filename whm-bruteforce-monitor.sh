#!/bin/bash

# -----------------------------------------------------------------------------
# WHM / cPanel Bruteforce Monitoring service
# Description: This script is used to monitor the bruteforce login attempts to the WHM / cPanel server.
# It will block the IP addresses that have more than 3 or 5 failed login attempts within 300 seconds.
# It will send a telegram alert to the admin if the IP address is blocked.
# It will also send a telegram alert if the IP address is not blocked.
# -----------------------------------------------------------------------------

LOGFILE="/usr/local/cpanel/logs/login_log"

BOT_TOKEN=""
CHAT_ID=""

# Message Thread ID for Telegram Forum/Topic Group
# 
THREAD_ID=""

HOSTNAME=$(hostname)

# -----------------------------------------------------------------------------
# CONFIG

# number of failed logins before blocking
THRESHOLD=5

# count time window (seconds)
WINDOW=300

# cooldown telegram alert per IP
ALERT_COOLDOWN=1800

# Tag block CSF
BLOCK_REASON="WHM Bruteforce Attack"

# IP whitelist (space separated, CIDR supported)
WHITELIST_IPS="1.2.3.0/24 113.111.11.110 31.2.4.11"

# rate limit: max log lines processed per second
# prevent overload during massive attacks
MAX_LINES_PER_SEC=100

# TTL cache whitelist & blocked (seconds)
CACHE_TTL=3600

# -----------------------------------------------------------------------------

STATE_DIR="/tmp/whm_monitor"
COUNT_DIR="${STATE_DIR}/counts"
ALERT_DIR="${STATE_DIR}/alerts"
CACHE_DIR="${STATE_DIR}/cache"

mkdir -p "$COUNT_DIR"
mkdir -p "$ALERT_DIR"
mkdir -p "$CACHE_DIR"

# -----------------------------------------------------------------------------
# FUNCTIONS

send_telegram() {

    local MESSAGE="$1"

    local CURL_PARAMS=(
        -s
        --max-time 10
        --retry 3
        --retry-delay 2
        -X POST
        "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"
        -d "chat_id=${CHAT_ID}"
        -d "text=${MESSAGE}"
        -d "parse_mode=HTML"
    )

    # Add message_thread_id if THREAD_ID is filled
    if [ -n "$THREAD_ID" ]; then
        CURL_PARAMS+=(-d "message_thread_id=${THREAD_ID}")
    fi

    curl "${CURL_PARAMS[@]}" >/dev/null 2>&1
}
# -----------------------------------------------------------------------------

is_valid_timestamp() {

    local VALUE="$1"
    [[ "$VALUE" =~ ^[0-9]+$ ]]
}

cache_is_fresh() {

    local CACHE_FILE="$1"
    local TTL="$2"
    local CACHE_TIME
    local CACHE_AGE

    [ -f "$CACHE_FILE" ] || return 1

    CACHE_TIME=$(cat "$CACHE_FILE" 2>/dev/null)
    if ! is_valid_timestamp "$CACHE_TIME"; then
        rm -f "$CACHE_FILE"
        return 1
    fi

    CACHE_AGE=$(( $(date +%s) - CACHE_TIME ))
    if [ "$CACHE_AGE" -lt "$TTL" ]; then
        return 0
    fi

    rm -f "$CACHE_FILE"
    return 1
}

write_cache_timestamp() {

    local CACHE_FILE="$1"
    date +%s > "$CACHE_FILE"
}

is_valid_ipv4() {

    local IP="$1"
    local IFS=.
    local -a OCTETS
    local OCTET
    local VALUE

    [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    OCTETS=($IP)
    [ "${#OCTETS[@]}" -eq 4 ] || return 1

    for OCTET in "${OCTETS[@]}"; do
        [[ "$OCTET" =~ ^[0-9]+$ ]] || return 1
        VALUE=$((10#$OCTET))
        [ "$VALUE" -ge 0 ] && [ "$VALUE" -le 255 ] || return 1
    done

    return 0
}

extract_attack_ip() {

    local LINE="$1"

    echo "$LINE" | sed -nE '
        /FAILED LOGIN (whostmgrd|cpaneld):/ {
            /POST \/login\// {
                s/.*\[(whostmgrd|cpaneld)\][[:space:]]+([0-9]{1,3}(\.[0-9]{1,3}){3})[[:space:]]+-[[:space:]]+root[[:space:]]+".*/\2/p
            }
        }
    '
}

# -----------------------------------------------------------------------------

# Support CIDR notation using python3
# + cache results to avoid repeated python3 spawns for the same IP
is_whitelisted() {

    local IP="$1"
    local CACHE_FILE="${CACHE_DIR}/wl_${IP}"

    # use cache if still in TTL
    if cache_is_fresh "$CACHE_FILE" "$CACHE_TTL"; then
        return 0
    fi

    for WHITE in $WHITELIST_IPS; do
        if echo "$WHITE" | grep -q '/'; then
            # CIDR check via python3
            if python3 -c "
import ipaddress, sys
try:
    result = ipaddress.ip_address('$IP') in ipaddress.ip_network('$WHITE', strict=False)
    sys.exit(0 if result else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
                # save to cache
                write_cache_timestamp "$CACHE_FILE"
                return 0
            fi
        else
            if [ "$IP" == "$WHITE" ]; then
                write_cache_timestamp "$CACHE_FILE"
                return 0
            fi
        fi
    done

    return 1
}

# -----------------------------------------------------------------------------
# Check if the IP is blocked in CSF
# + cache the results to avoid repeated calls to csf -g
already_blocked() {

    local IP="$1"
    local CACHE_FILE="${CACHE_DIR}/blocked_${IP}"

    # if the cache block is still fresh, skip csf -g
    if cache_is_fresh "$CACHE_FILE" "$CACHE_TTL"; then
        return 0
    fi

    if csf -g "$IP" 2>/dev/null | grep -qi "DENY"; then
        # save to TTL cache so that manual unblock in CSF can still be read again
        write_cache_timestamp "$CACHE_FILE"
        return 0
    fi

    return 1
}

# -----------------------------------------------------------------------------
# Delete files whose count exceeds WINDOW
# called periodically from the main loop
cleanup_stale_counts() {

    local NOW_CLEAN
    NOW_CLEAN=$(date +%s)
    local EXPIRE=$((NOW_CLEAN - WINDOW))

    local COUNT_FILE
    local FIRST_TIME

    for COUNT_FILE in "$COUNT_DIR"/*; do
        [ -f "$COUNT_FILE" ] || continue
        FIRST_TIME=$(cut -d: -f1 "$COUNT_FILE" 2>/dev/null)
        [ -z "$FIRST_TIME" ] && rm -f "$COUNT_FILE" && continue
        if [ "$FIRST_TIME" -lt "$EXPIRE" ]; then
            rm -f "$COUNT_FILE"
        fi
    done
}

process_attack() {

    local IP="$1"
    local LINE="$2"

    NOW=$(date +%s)

    COUNT_FILE="${COUNT_DIR}/${IP}"
    ALERT_FILE="${ALERT_DIR}/${IP}"

    # init counter

    if [ ! -f "$COUNT_FILE" ]; then
        echo "${NOW}:1" > "$COUNT_FILE"
        return
    fi

    DATA=$(cat "$COUNT_FILE")

    FIRST_TIME=$(echo "$DATA" | cut -d: -f1)
    COUNT=$(echo "$DATA" | cut -d: -f2)

    DIFF=$((NOW - FIRST_TIME))

    # reset window

    if [ "$DIFF" -gt "$WINDOW" ]; then
        # window expired — delete old files then re-init
        rm -f "$COUNT_FILE"
        echo "${NOW}:1" > "$COUNT_FILE"
        return
    fi

    COUNT=$((COUNT + 1))

    echo "${FIRST_TIME}:${COUNT}" > "$COUNT_FILE"

    # threshold reached

    if [ "$COUNT" -ge "$THRESHOLD" ]; then

        # skip if whitelist
        if is_whitelisted "$IP"; then
            return
        fi

        # skip if it has been blocked
        if already_blocked "$IP"; then
            return
        fi

        # block IP and make sure CSF is successful before cache
        BLOCK_STATUS="CSF AUTO BLOCKED"

        if csf -d "$IP" "$BLOCK_REASON" >/dev/null 2>&1; then
            write_cache_timestamp "${CACHE_DIR}/blocked_${IP}"
            echo "[INFO] IP blocked by CSF: ${IP}"
        else
            BLOCK_STATUS="CSF BLOCK FAILED"
            echo "[ERROR] Failed to block IP with CSF: ${IP}"
        fi

        # cooldown alert
        SEND_ALERT=1

        if [ -f "$ALERT_FILE" ]; then

            LAST_ALERT=$(cat "$ALERT_FILE")
            ALERT_DIFF=$((NOW - LAST_ALERT))

            if [ "$ALERT_DIFF" -lt "$ALERT_COOLDOWN" ]; then
                SEND_ALERT=0
            fi
        fi

        if [ "$SEND_ALERT" -eq 1 ]; then

            echo "$NOW" > "$ALERT_FILE"

            # Extract timestamps from log lines for neater display
            LOG_TIME=$(echo "$LINE" | awk '{print $1, $2}' | tr -d '[]')

            MESSAGE="🚨 <b>WHM and cPanel Bruteforce Detected</b>
━━━━━━━━━━━━━━━━━━━━
🖥 <b>Server</b>: <code>${HOSTNAME}</code>
👤 <b>Target</b>: <code>root</code>
🌐 <b>Attacker</b>: <code>${IP}</code>
🔥 <b>Action</b>: <code>${BLOCK_STATUS}</code>
📊 <b>Attempts</b>: <code>${COUNT}x / ${WINDOW}s</code>
🕐 <b>Time</b>: <code>${LOG_TIME}</code>
━━━━━━━━━━━━━━━━━━━━"

            send_telegram "$MESSAGE"
        fi

        # reset counter after threshold is processed
        rm -f "$COUNT_FILE"
    fi
}

# -----------------------------------------------------------------------------
# START MONITORING

echo "[INFO] WHM & cPanel Bruteforce Monitor Started..."

# rate limiter: counter and window per second
LINE_COUNT=0
WINDOW_START=$(date +%s)

# periodic cleanup tracker
LAST_CLEANUP=$(date +%s)

tail -F "$LOGFILE" | while read -r LINE
do

    NOW_SEC=$(date +%s)

    # PERIODIC CLEANUP
    # delete expired count files every 5 minutes

    if [ $((NOW_SEC - LAST_CLEANUP)) -gt 300 ]; then
        cleanup_stale_counts
        LAST_CLEANUP=$NOW_SEC
    fi

    # LOG FILTER + IP EXTRACTION
    # Grab IPs only from explicit whostmgrd patterns, regardless of the $6 field

    IP=$(extract_attack_ip "$LINE")

    # validate IPv4 format and range
    is_valid_ipv4 "$IP" || continue

    # RATE LIMITER
    # prevent overload during massive attacks; only count valid failed logins

    if [ "$NOW_SEC" -gt "$WINDOW_START" ]; then
        LINE_COUNT=0
        WINDOW_START=$NOW_SEC
    fi

    LINE_COUNT=$((LINE_COUNT + 1))

    if [ "$LINE_COUNT" -gt "$MAX_LINES_PER_SEC" ]; then
        continue
    fi

    process_attack "$IP" "$LINE"

done
