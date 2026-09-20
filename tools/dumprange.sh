#!/system/bin/sh
# dump /proc/PID/mem 的任意地址区间（含前后偏移），用于离线看窗口。
# 用法: sh dumprange.sh <pid> <addr_hex> <before_hex> <after_hex> <out>
PID="$1"; ADDR="$2"; BEF="${3:-1000}"; AFT="${4:-4000}"; OUT="${5:-/data/local/tmp/win.bin}"
tohex() { printf 'obase=16; ibase=16; %s\n' "$(echo "$1" | tr 'a-f' 'A-F')" | bc; }
todec() { printf 'ibase=16; %s\n' "$(echo "$1" | tr 'a-f' 'A-F')" | bc; }
START=$(printf 'obase=16; ibase=16; %s - %s\n' "$(echo "$ADDR" | tr 'a-f' 'A-F')" "$(echo "$BEF" | tr 'a-f' 'A-F')" | bc)
LEN=$(printf 'obase=16; ibase=16; %s + %s\n' "$(echo "$BEF" | tr 'a-f' 'A-F')" "$(echo "$AFT" | tr 'a-f' 'A-F')" | bc)
SDEC=$(todec "$START"); LDEC=$(todec "$LEN")
echo "# addr=0x$ADDR start=0x$START len=$LDEC -> $OUT"
dd if=/proc/$PID/mem bs=1 skip=$SDEC count=$LDEC of="$OUT" 2>/dev/null
wc -c "$OUT"
