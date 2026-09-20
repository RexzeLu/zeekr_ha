#!/system/bin/sh
# 在 /proc/PID/mem 的区间内按字节搜 dex 魔数 64 65 78 0a 30 33 35 00 ("dex\n035\0")。
# 做法：dd 原始字节 -> xxd -p 成十六进制文本 -> tr 去掉换行 -> grep 固定 hex 串。
# grep -b 给出的是「十六进制字符流」里的偏移，除以 2 即为原始字节偏移。
# 用法: sh find_dex.sh <pid> <start_hex> <end_hex> [chunk_mb]
PID="$1"; RS="$2"; RE="$3"; CH=$(( ${4:-64} * 1048576 ))
todec() { printf 'ibase=16; %s\n' "$(echo "$1" | tr 'a-f' 'A-F')" | bc; }
S=$(todec "$RS"); E=$(todec "$RE")
N=$(printf '(%s - %s + %s - 1) / %s\n' "$E" "$S" "$CH" "$CH" | bc)
echo "# pid=$PID range=$RS-$RE chunk=${CH}B chunks=$N"
i=0
while [ "$i" -lt "$N" ]; do
  OFF=$(printf '%s + %s * %s\n' "$S" "$i" "$CH" | bc)
  SKIP=$(printf '%s / 4096\n' "$OFF" | bc)
  CNT=$(( CH / 4096 ))
  dd if=/proc/$PID/mem bs=4096 skip=$SKIP count=$CNT 2>/dev/null \
    | xxd -p -c 256 | tr -d '\n' \
    | grep -o -b -E '6465780a30333500' \
    | while IFS=: read -r pos val; do
        ABS=$(printf '%s + %s / 2\n' "$OFF" "$pos" | bc)
        echo "DEXMAGIC $ABS"
      done
  echo "# chunk $i done (base $OFF)"
  i=$(( i + 1 ))
done
echo "# done"
