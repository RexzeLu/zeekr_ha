#!/system/bin/sh
# 列出 App 私有目录里的配置文件并搜密钥形态的键值（只读）
PKG=com.zeekrlife.mobile
echo "=== shared_prefs ==="
ls -la /data/data/$PKG/shared_prefs/ 2>/dev/null
for f in /data/data/$PKG/shared_prefs/*.xml; do
  [ -f "$f" ] || continue
  echo "--- $f ---"
  grep -o -a -E '<string name="[^"]{0,60}">[^<]{0,160}</string>' "$f" 2>/dev/null | grep -i -E 'secret|key|sign|token|appid|url|host' | head -40
done
echo "=== files dir (mmkv etc, top 40) ==="
ls -la /data/data/$PKG/files/ 2>/dev/null | head -40
echo "=== mmkv candidates ==="
find /data/data/$PKG -maxdepth 3 -iname '*mmkv*' 2>/dev/null | head -20
echo "=== db/datastore ==="
ls -la /data/data/$PKG/databases/ 2>/dev/null | head -20
echo "# done"
