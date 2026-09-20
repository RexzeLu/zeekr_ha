#!/system/bin/sh
# 对一组地址逐个 dump 窗口（±可调），每个写到 /data/local/tmp/hit_<addr>.bin
# 用法: sh dump_hits.sh <pid> <before_hex> <after_hex> <addr1> <addr2> ...
PID="$1"; BEF="$2"; AFT="$3"; shift 3
tohex() { printf 'obase=16; ibase=16; %s\n' "$(echo "$1" | tr 'a-f' 'A-F')" | bc; }
todec() { printf 'ibase=16; %s\n' "$(echo "$1" | tr 'a-f' 'A-F')" | bc; }
for A in "$@"; do
  UP=$(echo "$A" | tr 'a-f' 'A-F')
  START=$(printf 'obase=16; ibase=16; %s - %s\n' "$UP" "$(echo "$BEF" | tr 'a-f' 'A-F')" | bc)
  LEN=$(printf 'obase=16; ibase=16; %s + %s\n' "$(echo "$BEF" | tr 'a-f' 'A-F')" "$(echo "$AFT" | tr 'a-f' 'A-F')" | bc)
  SDEC=$(todec "$START"); LDEC=$(todec "$LEN")
  OUT="/data/local/tmp/hit_$A.bin"
  echo "# addr=0x$A start=0x$START len=$LDEC -> $OUT"
  dd if=/proc/$PID/mem bs=1 skip=$SDEC count=$LDEC of="$OUT" 2>/dev/null
  wc -c "$OUT"
done
echo "# done"
