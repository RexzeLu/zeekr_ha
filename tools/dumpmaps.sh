#!/system/bin/sh
# dump 目标进程内匹配某个文件名的所有内存区域（含区域头），便于离线分析。
# 用法: sh dumpmaps.sh <pid> <name-substring> <out>
PID="$1"
FILT="$2"
OUT="$3"
[ -z "$OUT" ] && OUT=/data/local/tmp/dumpmaps.bin
: > "$OUT"
echo "# pid=$PID filter=$FILT -> $OUT"
cat /proc/$PID/maps | grep "$FILT" | while read -r RANGE PERM OFF DEV INO NAME; do
  START=${RANGE%-*}
  END=${RANGE#*-}
  S=$((0x$START))
  E=$((0x$END))
  SZ=$((E - S))
  [ "$SZ" -le 0 ] && continue
  # 区域头写进同一个文件，便于离线切分
  printf '===MAP %s %s %s %s %s\n' "$RANGE" "$PERM" "$OFF" "$DEV" "$NAME" >> "$OUT"
  dd if=/proc/$PID/mem bs=4096 skip=$((S/4096)) count=$(( (SZ+4095)/4096 )) 2>/dev/null >> "$OUT"
  printf '\n===ENDMAP\n' >> "$OUT"
  echo "  dumped $RANGE $PERM $NAME ($SZ bytes)"
done
echo "# total: $(wc -c < $OUT) bytes"
