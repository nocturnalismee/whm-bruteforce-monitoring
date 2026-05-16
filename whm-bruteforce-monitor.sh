#!/bin/bash

# -----------------------------------------------------------------------------
# WHM / cPanel Bruteforce Monitoring service
# Description: This script is used to monitor the bruteforce login attempts to the WHM / cPanel server.
# It will block the IP addresses that exceed the failed login threshold within the configured time window.
# It will send a telegram alert to the admin when an IP is blocked or when blocking fails.
# -----------------------------------------------------------------------------
SERVER_HOSTNAME=$(hostname)
LOGFILE="/usr/local/cpanel/logs/login_log"

# -----------------------------------------------------------------------------
# CONFIG

BOT_TOKEN=""
CHAT_ID=""
THREAD_ID="" # Message Thread ID for Telegram Forum/Topic Group (Opsional)

# number of failed logins before blocking
THRESHOLD=5

# count time window (seconds)
WINDOW=300

# cooldown telegram alert per IP
ALERT_COOLDOWN=1800

# Tag block CSF (per service type)
BLOCK_REASON_WHM="WHM Root Bruteforce Attack"
BLOCK_REASON_CPANEL="cPanel Root Bruteforce Attack"

# IP whitelist (space separated, CIDR supported)
WHITELIST_IPS="1.1.1.1 10.2.3.0/24"

# rate limit: max log lines processed per second
# prevent overload during massive attacks
MAX_LINES_PER_SEC=100

# TTL cache whitelist & blocked (seconds)
CACHE_TTL=3600

# cleanup interval: how often to sweep stale files (seconds)
# default 300 = every 5 minutes
CLEANUP_INTERVAL=300

# -----------------------------------------------------------------------------

STATE_DIR="/etc/monitor/bruteforce-log"
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
        --data-urlencode "text=${MESSAGE}"
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

is_valid_count_state() {

    local VALUE="$1"
    [[ "$VALUE" =~ ^[0-9]+:[0-9]+$ ]]
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
            # CIDR check via python3 (using sys.argv to prevent injection)
            if python3 -c "
import ipaddress, sys
try:
    result = ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False)
    sys.exit(0 if result else 1)
except Exception:
    sys.exit(1)
" "$IP" "$WHITE" 2>/dev/null; then
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
# Delete stale files across all state directories
# called periodically from the main loop
cleanup_stale_files() {

    local NOW_CLEAN
    NOW_CLEAN=$(date +%s)

    local FILE
    local FILE_TIME
    local FILE_DATA

    # --- cleanup counts/ (expire after WINDOW) ---
    local EXPIRE_COUNTS=$((NOW_CLEAN - WINDOW))
    for FILE in "$COUNT_DIR"/*; do
        [ -f "$FILE" ] || continue
        FILE_DATA=$(cat "$FILE" 2>/dev/null)
        if ! is_valid_count_state "$FILE_DATA"; then
            rm -f "$FILE"
            continue
        fi
        FILE_TIME="${FILE_DATA%%:*}"
        if [ "$FILE_TIME" -lt "$EXPIRE_COUNTS" ]; then
            rm -f "$FILE"
        fi
    done

    # --- cleanup alerts/ (expire after ALERT_COOLDOWN x3) ---
    local EXPIRE_ALERTS=$((NOW_CLEAN - ALERT_COOLDOWN * 3))
    for FILE in "$ALERT_DIR"/*; do
        [ -f "$FILE" ] || continue
        FILE_TIME=$(cat "$FILE" 2>/dev/null)
        if ! is_valid_timestamp "$FILE_TIME"; then
            rm -f "$FILE"
            continue
        fi
        if [ "$FILE_TIME" -lt "$EXPIRE_ALERTS" ]; then
            rm -f "$FILE"
        fi
    done

    # --- cleanup cache/ (expire after CACHE_TTL) ---
    local EXPIRE_CACHE=$((NOW_CLEAN - CACHE_TTL))
    for FILE in "$CACHE_DIR"/*; do
        [ -f "$FILE" ] || continue
        FILE_TIME=$(cat "$FILE" 2>/dev/null)
        if ! is_valid_timestamp "$FILE_TIME"; then
            rm -f "$FILE"
            continue
        fi
        if [ "$FILE_TIME" -lt "$EXPIRE_CACHE" ]; then
            rm -f "$FILE"
        fi
    done
}

process_attack() {

    local IP="$1"
    local LINE="$2"

    local NOW
    NOW=$(date +%s)

    local COUNT_FILE="${COUNT_DIR}/${IP}"
    local ALERT_FILE="${ALERT_DIR}/${IP}"

    # detect service type from log line
    local SERVICE_TYPE="WHM"
    local BLOCK_REASON="$BLOCK_REASON_WHM"
    if echo "$LINE" | grep -q '\[cpaneld\]'; then
        SERVICE_TYPE="cPanel"
        BLOCK_REASON="$BLOCK_REASON_CPANEL"
    fi

    # init counter

    if [ ! -f "$COUNT_FILE" ]; then
        echo "${NOW}:1" > "$COUNT_FILE"
        return
    fi

    local DATA
    DATA=$(cat "$COUNT_FILE")

    if ! is_valid_count_state "$DATA"; then
        rm -f "$COUNT_FILE"
        echo "${NOW}:1" > "$COUNT_FILE"
        return
    fi

    local FIRST_TIME
    FIRST_TIME="${DATA%%:*}"
    local COUNT
    COUNT="${DATA#*:}"

    local DIFF=$((NOW - FIRST_TIME))

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
        local BLOCK_STATUS="CSF AUTO BLOCKED ✅"
        local BLOCK_SUCCESS=1
        local CSF_ERROR=""

        local CSF_OUTPUT
        CSF_OUTPUT=$(csf -d "$IP" "$BLOCK_REASON" 2>&1)
        if [ $? -eq 0 ]; then
            write_cache_timestamp "${CACHE_DIR}/blocked_${IP}"
            echo "[INFO] IP blocked by CSF: ${IP} (${SERVICE_TYPE})"
        else
            BLOCK_STATUS="CSF BLOCK FAILED ❌"
            BLOCK_SUCCESS=0
            CSF_ERROR="$CSF_OUTPUT"
            echo "[ERROR] Failed to block IP with CSF: ${IP} — ${CSF_OUTPUT}"
        fi

        # cooldown alert
        local SEND_ALERT=1

        if [ -f "$ALERT_FILE" ]; then

            local LAST_ALERT
            LAST_ALERT=$(cat "$ALERT_FILE")

            if ! is_valid_timestamp "$LAST_ALERT"; then
                rm -f "$ALERT_FILE"
            else
                local ALERT_DIFF=$((NOW - LAST_ALERT))

                if [ "$ALERT_DIFF" -lt "$ALERT_COOLDOWN" ]; then
                    SEND_ALERT=0
                fi
            fi
        fi

        if [ "$SEND_ALERT" -eq 1 ]; then

            echo "$NOW" > "$ALERT_FILE"

            # Extract timestamps from log lines for neater display
            local LOG_TIME
            LOG_TIME=$(echo "$LINE" | awk '{print $1, $2}' | tr -d '[]')

            local MESSAGE="<b>${SERVICE_TYPE} Bruteforce Detected</b>

<b>Server:</b>  <code>${SERVER_HOSTNAME}</code>
<b>Target:</b>  <code>root</code>
<b>Attacker:</b>  <code>${IP}</code>
<b>Attempts:</b>  <code>${COUNT}x</code> dalam <code>${WINDOW}s</code>
<b>Time:</b>  <code>${LOG_TIME}</code>

🔥  <b>Action:</b>  ${BLOCK_STATUS}"

            # append CSF error detail if block failed
            if [ -n "$CSF_ERROR" ]; then
                MESSAGE+="
⚠️  <b>Error:</b>  <code>${CSF_ERROR}</code>"
            fi

            send_telegram "$MESSAGE"
        fi

        # reset counter only if block was successful
        if [ "$BLOCK_SUCCESS" -eq 1 ]; then
            rm -f "$COUNT_FILE"
        fi
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

while read -r LINE
do

    NOW_SEC=$(date +%s)

    # PERIODIC CLEANUP

    if [ $((NOW_SEC - LAST_CLEANUP)) -gt "$CLEANUP_INTERVAL" ]; then
        cleanup_stale_files
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

done < <(tail -F "$LOGFILE")
