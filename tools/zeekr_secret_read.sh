#!/system/bin/sh
# 读取 libHttpSecretKey.so 的 secret 全局变量（vaddr 0x54c40）及其 rw 数据段。
#
# 依据（对 _cmp/nativelib/libHttpSecretKey.so 反汇编确认）：
#   setSecretKey: env->GetStringUTFChars(key,NULL) 返回值 -> str 到 vaddr 0x54c40
#   getSecretKey: ldr vaddr 0x54c40 -> env->NewStringUTF(ptr) 返回 jstring
# 故 0x54c40 处 8 字节 = char*，指向明文密钥（若为 0 表示尚未调用 setSecretKey）。
#
# 注意：Android mksh 的 $(( )) 是 32 位，装不下 0x7a... 的库地址，故进制换算全走 bc。
# 用法: sh zeekr_secret_read.sh [pid] [outfile]
PID="$1"
OUT="${2:-/data/local/tmp/hsk_rw.bin}"
[ -z "$PID" ] && PID=$(pidof com.zeekrlife.mobile)
[ -z "$PID" ] && { echo "ERR: no pid"; exit 1; }
MAPS=/proc/$PID/maps
echo "# pid=$PID"

tohex() { printf 'obase=16; ibase=16; %s\n' "$(echo "$1" | tr 'a-f' 'A-F')" | bc; }
todec() { printf 'ibase=16; %s\n' "$(echo "$1" | tr 'a-f' 'A-F')" | bc; }

BASE=$(grep 'libHttpSecretKey\.so' "$MAPS" | grep ' 00000000 ' | head -n1 | cut -d- -f1)
[ -z "$BASE" ] && BASE=$(grep 'libHttpSecretKey\.so' "$MAPS" | head -n1 | cut -d- -f1)
[ -z "$BASE" ] && { echo "ERR: libHttpSecretKey.so 未加载"; exit 2; }
GH=$(printf 'obase=16; ibase=16; %s + 54C40\n' "$(echo "$BASE" | tr 'a-f' 'A-F')" | bc)
GDEC=$(todec "$GH")
echo "# base=0x$BASE  global=0x$GH  (dec $GDEC)"

RAW=$(dd if=/proc/$PID/mem bs=1 skip=$GDEC count=8 2>/dev/null | od -An -v -tx1 | tr -d ' \n')
echo "# raw8=$RAW"
if [ ${#RAW} -eq 16 ]; then
  REV="${RAW:14:2}${RAW:12:2}${RAW:10:2}${RAW:8:2}${RAW:6:2}${RAW:4:2}${RAW:2:2}${RAW:0:2}"
  PDEC=$(todec "$REV")
  echo "# secret_ptr=0x$REV"
  if [ "$PDEC" != "0" ]; then
    echo "=== SECRET STRING @ ptr ==="
    dd if=/proc/$PID/mem bs=1 skip=$PDEC count=256 2>/dev/null | tr -d '\000'
    echo ""
  else
    echo "# ptr=0 -> App 尚未调用 setSecretKey()"
  fi
fi

# dump libHttpSecretKey.so 的 rw 段（.data+.bss）
RWS=$(grep 'libHttpSecretKey\.so' "$MAPS" | grep ' rw-p ' | head -n1 | cut -d- -f1)
RWE=$(grep 'libHttpSecretKey\.so' "$MAPS" | grep ' rw-p ' | head -n1 | cut -d- -f2)
if [ -n "$RWS" ]; then
  RDEC=$(todec "$RWS"); EDEC=$(todec "$RWE")
  SZ=$(( (EDEC - RDEC) / 2 + (EDEC - RDEC) / 2 ))   # 避免 mksh 32 位问题: 双半相加
  echo "=== rw segment 0x$RWS..0x$RWE (dec sz $SZ) -> $OUT ==="
  dd if=/proc/$PID/mem bs=1 skip=$RDEC count=$SZ of="$OUT" 2>/dev/null
  wc -c "$OUT"
fi
echo "# done"
