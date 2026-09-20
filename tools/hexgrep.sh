#!/system/bin/sh
# 在 /proc/PID/mem 区间里按【十六进制】模式搜索（可跨换行等不可打印字节），
# 命中后立刻 dump 命中点 ±窗口。避开 shell 正则不能跨行的限制。
# 用法: sh hexgrep.sh <pid> <start_hex> <end_hex> <hex_pattern> <before_hex> <after_hex> <prefix> [max_hits] [chunk_mb]
PID="$1"; RS="$2"; RE="$3"; HP="$4"; BEF="$5"; AFT="$6"; PFX="${7:-hx}"; MAX="${8:-8}"; CH=$(( ${9:-96} * 1048576 ))
todec() { printf 'ibase=16; %s\n' "$(echo "$1" | tr 'a-f' 'A-F')" | bc; }
S=$(todec "$RS"); E=$(todec "$RE")
N=$(printf '(%s - %s + %s - 1) / %s\n' "$E" "$S" "$CH" "$CH" | bc)
echo "# pid=$PID range=$RS-$RE chunk=${CH}B chunks=$N pat_hex=$HP"
LIST=/data/local/tmp/${PFX}_list.txt
: > "$LIST"
i=0
while [ "$i" -lt "$N" ]; do
  OFF=$(printf '%s + %s * %s\n' "$S" "$i" "$CH" | bc)
  SKIP=$(printf '%s / 4096\n' "$OFF" | bc)
  CNT=$(( CH / 4096 ))
  dd if=/proc/$PID/mem bs=4096 skip=$SKIP count=$CNT 2>/dev/null \
    | xxd -p -c 256 | tr -d '\n' \
    | grep -o -b -E "$HP" \
    | while IFS=: read -r pos val; do
        ABS=$(printf '%s + %s / 2\n' "$OFF" "$pos" | bc)
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
  echo "HIT#$IDX abs=$ABS out=$OUT size=$(wc -c < $OUT 2>/dev/null)"
done < "$LIST"
echo "# done"
