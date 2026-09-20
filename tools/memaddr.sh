#!/system/bin/sh
# 在设备端分块扫描进程某个地址区间的内存，输出模式命中的绝对地址。
# 用法: sh memaddr.sh <pid> <start_hex> <end_hex> <regex> [chunk_mb]
PID="$1"; RSTART="$2"; REND="$3"; PAT="$4"; CH=$(( ${5:-32} * 1048576 ))
S=$((0x$RSTART)); E=$((0x$REND))
N=$(( (E - S + CH - 1) / CH ))
echo "# range $RSTART-$REND chunk=${CH}B chunks=$N"
i=0
while [ $i -lt $N ]; do
  OFF=$((S + i * CH))
  CNT=$(( CH / 4096 ))
  dd if=/proc/$PID/mem bs=4096 skip=$(( OFF / 4096 )) count=$CNT 2>/dev/null \
    | grep -a -b -o -E "$PAT" \
    | while IFS=: read -r pos val; do
        echo "$(( OFF + pos )) $val"
      done
  i=$(( i + 1 ))
done
echo "# done"
