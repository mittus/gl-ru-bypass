#!/usr/bin/env bash


set -euo pipefail

DIST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dist"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Источники
DOMAINS_URL="${DOMAINS_URL:-https://raw.githubusercontent.com/UnRKN/ru-blocklist/main/ru-blocklist-ext.txt}"
IPV4_URL="${IPV4_URL:-https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone}"
TLDS_URL="${TLDS_URL:-https://data.iana.org/TLD/tlds-alpha-by-domain.txt}"

# Прошивка GL.iNet принимает только домены, у которых каждая часть начинается с
# буквы, а зона состоит из букв. Поэтому правила на зоны целиком («ru», «su»,
# «xn--p1ai»), домены с цифры («2gis.com») и punycode-зоны («nalog.xn--p1ai»)
# роутер отвергает — они складываются в dist/rejected.txt и в списки не попадают.
DOMAIN_RE='^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*\.[a-z]+$'

say() { printf '%s\n' "$*" >&2; }

fetch() {
    local url="$1" out="$2"
    curl -fsSL --max-time 120 "$url" -o "$out" \
        || { say "ОШИБКА: не скачать $url"; exit 1; }
}

say "Скачиваю список доменов…"
fetch "$DOMAINS_URL" "$WORK/domains.raw"
say "Скачиваю подсети РФ…"
fetch "$IPV4_URL" "$WORK/ipv4.raw"
say "Скачиваю реестр доменных зон IANA…"
fetch "$TLDS_URL" "$WORK/tlds.raw"
grep -v '^#' "$WORK/tlds.raw" | tr 'A-Z' 'a-z' | tr -d '\r' | sort -u > "$WORK/tlds.list"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$DIST"

# --- домены -----------------------------------------------------------------
{
    cat "$WORK/domains.raw"
    [ -f "$here/extra-domains.txt" ] && cat "$here/extra-domains.txt"
} | tr -d '\r' \
  | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^\.//' \
  | grep -E '^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$' \
  | tr 'A-Z' 'a-z' | sort -u > "$WORK/domains.clean"

# оставляем только то, что примет роутер; остальное — в rejected.txt.
# Дополнительно сверяем зону с реестром IANA: так отсеиваются опечатки
# в источнике (например, «sber.f»), которые роутер тоже не принимает.
grep -E "$DOMAIN_RE" "$WORK/domains.clean" | sort -u > "$WORK/domains.syntax_ok"
grep -vE "$DOMAIN_RE" "$WORK/domains.clean" | sort -u > "$WORK/domains.rejected"

awk 'NR==FNR { tld[$0]=1; next }
     { n=split($0, p, "."); if (p[n] in tld) print > OK; else print > BAD }' \
    OK="$WORK/domains.tld_ok" BAD="$WORK/domains.tld_bad" \
    "$WORK/tlds.list" "$WORK/domains.syntax_ok"
touch "$WORK/domains.tld_ok" "$WORK/domains.tld_bad"

sort -u "$WORK/domains.tld_ok" > "$DIST/ru-bypass-domains.txt"
cat "$WORK/domains.rejected" "$WORK/domains.tld_bad" | sort -u > "$DIST/rejected.txt"

# --- подсети ----------------------------------------------------------------
tr -d '\r' < "$WORK/ipv4.raw" \
  | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' \
  | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$DIST/ru-bypass-ip.txt"

# --- всё вместе -------------------------------------------------------------
cat "$DIST/ru-bypass-domains.txt" "$DIST/ru-bypass-ip.txt" > "$DIST/ru-bypass-full.txt"

say ""
say "Готово:"
for f in ru-bypass-domains.txt ru-bypass-ip.txt ru-bypass-full.txt; do
    say "  dist/$f — $(wc -l < "$DIST/$f") строк, $(du -h "$DIST/$f" | cut -f1)"
done
rejected=$(wc -l < "$DIST/rejected.txt")
if [ "$rejected" -gt 0 ]; then
    say "  dist/rejected.txt — $rejected строк, которые роутер не принимает"
fi
