#!/system/bin/sh
# 在设备端扫描目标进程的可读内存，定位关键字符串所在区域。
# 用法: sh memscan.sh <pid> <regex>
PID="$1"
PAT="$2"
[ -z "$PID" ] && echo "usage: memscan.sh <pid> <regex>" && exit 1
[ -z "$PAT" ] && PAT='GEELYCNCH[0-9A-Z]*|ZEEKRCNCH[0-9A-Z]*'

echo "# scanning pid=$PID pattern=$PAT"
cat /proc/$PID/maps | grep ' r' | while read -r RANGE PERM OFF DEV INO NAME; do
  START=${RANGE%-*}
  END=${RANGE#*-}
  S=$((0x$START))
  E=$((0x$END))
  SZ=$((E - S))
  [ "$SZ" -le 0 ] && continue
  SKIP=$((S / 4096))
  CNT=$(( (SZ + 4095) / 4096 ))
  # 只统计命中数，避免把整块内存写进管道
  N=$(dd if=/proc/$PID/mem bs=4096 skip=$SKIP count=$CNT 2>/dev/null | grep -a -o -E "$PAT" | wc -l)
  N=$(echo "$N" | tr -d ' ')
  if [ -n "$N" ] && [ "$N" != "0" ]; then
    SAMPLE=$(dd if=/proc/$PID/mem bs=4096 skip=$SKIP count=$CNT 2>/dev/null | grep -a -o -E "$PAT" | sort -u | tr '\n' ',')
    echo "HIT x$N @ $RANGE $PERM $NAME  :: $SAMPLE"
  fi
done
echo "# done"
