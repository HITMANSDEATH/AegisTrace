#!/bin/sh
# Render the Nginx gateway config from validated environment values, then run Nginx.
set -eu

fail() { echo "frontend-entrypoint: $*" >&2; exit 1; }
trim() { printf '%s' "$1" | tr -d '[:space:]'; }

positive_int() {
  name=$1
  value=$2
  default=$3
  [ -n "$value" ] || value=$default
  case "$value" in
    0|'') fail "$name must be a positive integer" ;;
    0*) fail "$name must not have leading zeros" ;;
    *[!0-9]*) fail "$name must be a positive integer" ;;
  esac
  printf '%s' "$value"
}

rate=$(positive_int LLM_RATE_LIMIT_PER_MINUTE "${LLM_RATE_LIMIT_PER_MINUTE:-}" 10)
body=$(positive_int MAX_REQUEST_BODY_BYTES "${MAX_REQUEST_BODY_BYTES:-}" 131072)

# Real-IP resolution is off by default: trusting a forwarded header from an
# untrusted source lets clients choose their own rate-limit identity.
: > /tmp/realip.conf
cidrs=${TRUSTED_PROXY_CIDR:-}
if [ -n "$cidrs" ]; then
  old_ifs=$IFS
  IFS=,
  for cidr in $cidrs; do
    cidr=$(trim "$cidr")
    [ -n "$cidr" ] || continue
    case "$cidr" in
      *[!0-9A-Fa-f:./]*) fail "TRUSTED_PROXY_CIDR entries must be IPv4/IPv6 CIDR ranges" ;;
      */*) ;;
      *) fail "TRUSTED_PROXY_CIDR entries must be CIDR ranges (address/prefix)" ;;
    esac
    address=${cidr%/*}
    prefix=${cidr#*/}
    case "$address" in ''|*/*) fail "TRUSTED_PROXY_CIDR contains an invalid address" ;; esac
    case "$prefix" in ''|*[!0-9]*) fail "TRUSTED_PROXY_CIDR contains an invalid prefix" ;; esac
    [ "$prefix" -le 128 ] || fail "TRUSTED_PROXY_CIDR prefix must be 128 or lower"
    echo "set_real_ip_from $cidr;" >> /tmp/realip.conf
  done
  IFS=$old_ifs
  if [ -s /tmp/realip.conf ]; then
    echo "real_ip_header X-Forwarded-For;" >> /tmp/realip.conf
    echo "real_ip_recursive on;" >> /tmp/realip.conf
  fi
fi

# Gateway-generated 413/429 responses carry CORS headers only for configured
# origins; proxied responses keep the agent/reconstruction CORS middleware.
default_origins='http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080,http://127.0.0.1:8080'
origins=${ALLOWED_ORIGINS-$default_origins}
{
  echo '# Generated from ALLOWED_ORIGINS.'
  echo 'map $http_origin $cors_origin {'
  echo '  default "";'
  if [ "$origins" = "*" ]; then
    echo '  "~.+" $http_origin;'
  else
    old_ifs=$IFS
    IFS=,
    for origin in $origins; do
      origin=$(trim "$origin")
      [ -n "$origin" ] || continue
      while [ "${origin%/}" != "$origin" ]; do origin=${origin%/}; done
      printf '%s' "$origin" | grep -Eq '^https?://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(:[0-9]+)?$' \
        || fail "ALLOWED_ORIGINS must contain scheme://host[:port] origins only"
      echo "  \"$origin\" \$http_origin;"
    done
    IFS=$old_ifs
  fi
  echo '}'
} > /tmp/corsmap.conf

template=/etc/nginx/nginx.conf.template
out=/tmp/nginx.conf
if command -v envsubst >/dev/null 2>&1; then
  envsubst '${LLM_RATE_LIMIT_PER_MINUTE} ${MAX_REQUEST_BODY_BYTES}' < "$template" > "$out"
else
  sed -e "s|\${LLM_RATE_LIMIT_PER_MINUTE}|$rate|g" \
      -e "s|\${MAX_REQUEST_BODY_BYTES}|$body|g" "$template" > "$out"
fi

nginx -t -c "$out"
exec nginx -c "$out" -g 'daemon off;'
