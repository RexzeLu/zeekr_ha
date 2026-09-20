#!/system/bin/sh
# 在某个 .so 目录里搜字符串（用于定位签名/密钥实现所在库）
# 用法: sh grep_libs.sh <libdir> <pat1> [pat2] ...
LIB="$1"; shift
for p in "$@"; do
  echo "--- $p ---"
  for f in "$LIB"/*.so; do
    [ -f "$f" ] || continue
    if grep -q -a -e "$p" "$f" 2>/dev/null; then
      echo "  $(basename "$f")"
    fi
  done
done
echo "# done"
