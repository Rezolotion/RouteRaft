# RouteRaft

مدیر تونل و روتینگ ماژولار برای لپ‌تاپ لینوکسی، روی **sing-box**.
یک TUN کل لپ‌تاپ را می‌گیرد؛ «نقشه‌ی روتینگ» جدا از «خروجی‌ها» است، پس عوض کردن
سرف‌شارک ↔ ویندسکرایب ↔ V2Ray یعنی عوض کردن یک فیلد، نه بازنویسی قوانین.

```
لپ‌تاپ ──TUN──▶ قوانین (به ترتیب) ──▶ direct   سایت‌های ایرانی (آی‌پی ایران)
                                   ├▶ corp     OpenVPN شرکت (فقط دامنه/آی‌پی‌های مشخص)
                                   └▶ global   (selector) یکی از: Surfshark | Windscribe | VLESS | VLESS-auto
```

## مفاهیم
| | |
|---|---|
| **exit** | یک خروجی: `wireguard` (سرف‌شارک/ویندسکرایب)، `vless` (نود ساب‌سکریپشن)، `direct`، `corp` |
| **global** | اسلات خروجی سراسری؛ همیشه یکی از wireguard/vless. بدون ری‌استارت عوض می‌شود (clash API) |
| **route** | یک قانون: تطابق (`domain_suffix`, `domain`, `ip_cidr`, `rule_set`, `process_name`) ← exit |

مقصد یک route می‌تواند `global`، `direct`، `corp` یا id یک خروجی خاص باشد.
ترتیب مهم است؛ اولین تطابق برنده است. پیش‌فرض نهایی: `global`.

## نصب (یک‌بار)
1. sing-box ≥ 1.12 و openvpn را نصب کنید (sing-box در مخزن Debian نیست؛ مخزن رسمی SagerNet یا release گیت‌هاب).
2. کپی پروژه و سرویس:
   ```bash
   sudo mkdir -p /opt/routeraft && sudo cp -r routeraft pyproject.toml /opt/routeraft/
   sudo cp packaging/routeraft.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now routeraft
   ```
3. UI: <http://127.0.0.1:8787>

> هنگام «وصل شو»، سرویس‌های `settings.stop_conflicting` (پیش‌فرض `v2raya`) متوقف و
> هنگام «قطع شو» دوباره روشن می‌شوند، چون هر دو روی TUN و DNS دست می‌گذارند.

## استفاده
- وایرگارد: فایل `.conf` سرف‌شارک/ویندسکرایب را در UI بچسبانید (یا `routeraft import-wg file.conf --name X`).
- V2Ray: لینک ساب‌سکریپشن یا لینک‌های `vless://` (یا `routeraft import-sub URL`).
- شرکت: مسیر `.ovpn` + فعال‌سازی. OpenVPN با `--route-nopull` اجرا می‌شود (روت و DNS پوش‌شده نادیده)،
  و فقط قوانینی که `corp` را هدف دارند به آن می‌روند. سرور OpenVPN خودش از TUN بیرون نگه داشته می‌شود.
- قوانین ایران: `routeraft update-rules` فایل‌های rule-set را کش می‌کند (وگرنه sing-box از طریق global دانلود می‌کند).

## توسعه
```bash
python3 -m unittest discover -s tests -v
python3 -m routeraft --state-dir dev-state serve --dry-run   # بدون دست زدن به شبکه
python3 -m routeraft --state-dir dev-state build             # کانفیگ sing-box را ببینید
```

## امنیت
دیمن root است و UI فقط روی `127.0.0.1` گوش می‌دهد. درخواست‌های تغییر نیاز به توکن per-install دارند و Host/Origin
بررسی می‌شود (ضد DNS-rebinding/CSRF). کلیدها و UUIDها هرگز از `/api/state` برنمی‌گردند. `state.json` مجوز 600 دارد.

## وضعیت
v0.1: هسته، تولید کانفیگ، UI و تست‌های واحد آماده‌اند. **هنوز با sing-box واقعی روی TUN آزمایش نشده**
(sing-box نصب نبود). این‌ها باید اولین بار روی لپ‌تاپ تأیید شوند: bind به `tun-corp`، سازگاری Docker با `strict_route`،
و نام فیلدهای کانفیگ با نسخه‌ی نصب‌شده (دیمن پیش از اجرا خودش `sing-box check` می‌زند).
