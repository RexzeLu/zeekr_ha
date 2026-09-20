#!/system/bin/sh
# 扫描区间内匹配正则的地址，并【同一会话内立刻】dump 每个命中点 ±窗口，
# 避免 dalvik region space 在两次 adb 调用之间移动对象导致地址失效。
# 用法: sh scan_dump.sh <pid> <start_hex> <end_hex> <regex> <before_hex> <after_hex> <prefix> [max_hits] [chunk_mb]
PID="$1"; RS="$2"; RE="$3"; PAT="$4"; BEF="$5"; AFT="$6"; PFX="${7:-hit}"; MAX="${8:-24}"; CH=$(( ${9:-64} * 1048576 ))
todec() { printf 'ibase=16; %s\n' "$(echo "$1" | tr 'a-f' 'A-F')" | bc; }
S=$(todec "$RS"); E=$(todec "$RE")
N=$(printf '(%s - %s + %s - 1) / %s\n' "$E" "$S" "$CH" "$CH" | bc)
echo "# pid=$PID range=$RS-$RE chunk=${CH}B chunks=$N pat=$PAT"
LIST=/data/local/tmp/${PFX}_list.txt
: > "$LIST"
i=0
while [ "$i" -lt "$N" ]; do
  OFF=$(printf '%s + %s * %s\n' "$S" "$i" "$CH" | bc)
  SKIP=$(printf '%s / 4096\n' "$OFF" | bc)
  CNT=$(( CH / 4096 ))
  dd if=/proc/$PID/mem bs=4096 skip=$SKIP count=$CNT 2>/dev/null \
    | grep -a -b -o -E "$PAT" \
    | while IFS=: read -r pos val; do
        ABS=$(printf '%s + %s\n' "$OFF" "$pos" | bc)
        echo "$ABS $val" >> "$LIST"
      done
  i=$(( i + 1 ))
done
echo "# hits: $(wc -l < $LIST)"
IDX=0
while read -r ABS VAL; do
  [ "$IDX" -ge "$MAX" ] && break
  IDX=$(( IDX + 1 ))
  START=$(printf '%s - %s\n' "$ABS" "$(todec "$BEF")" | bc)
  LEN=$(printf '%s + %s\n' "$(todec "$BEF")" "$(todec "$AFT")" | bc)
  OUT="/data/local/tmp/${PFX}_${IDX}_${ABS}.bin"
  dd if=/proc/$PID/mem bs=1 skip=$START count=$LEN of="$OUT" 2>/dev/null
  echo "HIT#$IDX abs=$ABS val=$VAL out=$OUT size=$(wc -c < $OUT 2>/dev/null)"
done < "$LIST"
echo "# done"
