# Defense XDR

**Davranış tabanlı, açık kaynaklı uç nokta güvenlik ajanı.**

İmza veritabanı yok. Telemetri yok. Verileriniz sadece sizin cihazınızda.

Defense, süreç davranışlarını, dosya sistemi değişikliklerini, ağ bağlantılarını, kayıt defteri değişikliklerini ve USB cihazlarını gerçek zamanlı izler. Kurallar TOML formatında — kod bilmeden kendi kurallarınızı yazabilirsiniz.

---

## Desteklenen Platformlar

- Windows 10/11
- Linux (Ubuntu 22.04+, Arch, Debian tabanlı)
- macOS 12+

---

## Kurulum

### Kaynak koddan derle (önerilen)

```bash
git clone https://github.com/Defense-open/defense-open.git
cd defense-open
cargo build --release
```

Binary çıktısı: `target/release/defense-agent`

### Gereksinimler

- Rust 1.78+ (`rustup` ile kurulum: https://rustup.rs)
- Windows'ta Registry ve USB kolektörleri için yönetici yetkisi gerekmez; ancak bazı sistem dizinlerini izlemek için yönetici olarak çalıştırmanız önerilir.

---

## Kullanım

```bash
# Tüm kolektörlerle başlat (varsayılan)
defense-agent --rules-dir ./rules

# Alert'leri dosyaya yaz
defense-agent --rules-dir ./rules --alert-file alerts.jsonl

# Sadece belirli kolektörler
defense-agent --rules-dir ./rules --collectors process,fs,network

# Yüksek skorlu alert'leri filtrele (jq gerektirir)
defense-agent --rules-dir ./rules | jq 'select(.score >= 70)'

# Yardım
defense-agent --help
```

### Kolektörler

| İsim | Ne İzler |
|------|----------|
| `process` | Yeni süreç oluşturma, komut satırı argümanları |
| `fs` | Dosya oluşturma, değiştirme, silme |
| `network` | Ağ arayüz istatistikleri, TCP bağlantıları (Linux) |
| `registry` | Windows kayıt defteri Run/Winlogon/Services anahtarları |
| `usb` | USB/çıkarılabilir disk bağlantısı |

---

## Alert Formatı

Her eşleşen kural için tek satır JSON çıktısı:

```json
{
  "timestamp": "2026-06-22T14:30:00Z",
  "event_id": 42,
  "rule_id": "PROC-001",
  "rule_name": "PowerShell Encoded Command",
  "score": 85,
  "category": "execution",
  "mitre": "T1059.001",
  "recommended_action": "investigate",
  "event": {
    "kind": "process",
    "pid": 1234,
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -EncodedCommand SQBFAFgA"
  }
}
```

**Skor:** 0–100 arası tehdit skoru. 70+ dikkat gerektiriyor, 90+ kritik.  
**MITRE:** Alert'in hangi ATT&CK tekniğiyle ilişkilendirildiği.

---

## Kural Yazımı

Kural dosyaları `rules/` dizininde `.toml` formatında. Kendiniz yazabilirsiniz:

```toml
[[rules]]
id = "CUSTOM-001"
name = "Şüpheli Python Betiği"
score = 60
category = "execution"
mitre = "T1059.006"
recommended_action = "investigate"
match_mode = "all"   # "all" = AND, "any" = OR

[[rules.conditions]]
field = "process.image"
op = "ends_with"
value = "python.exe"

[[rules.conditions]]
field = "process.command_line"
op = "contains"
value = "base64"
```

### Kullanılabilir Field'lar

| Prefix | Field'lar |
|--------|-----------|
| `process.` | `image`, `command_line`, `pid`, `parent_image` |
| `fs.` | `path`, `event_type` |
| `network.` | `dst_ip`, `dst_port`, `protocol`, `bytes_sent` |
| `registry.` | `key`, `value_name`, `operation` |
| `usb.` | `device_id`, `device_class` |

### Operatörler

`contains`, `not_contains`, `equals`, `not_equals`, `starts_with`, `ends_with`, `gt`, `lt`, `eq`

Tüm string karşılaştırmalar büyük/küçük harf duyarsızdır.

---

## Mevcut Kural Seti

50 kural, 5 kategori, tamamı MITRE ATT&CK etiketli:

- **Process (15):** PowerShell encoded command, Mimikatz, shadow copy silme, PsExec, WMI process creation...
- **FileSystem (15):** Ransomware uzantıları, LSASS dump, başlangıç klasörü, geçici dizin...
- **Network (10):** C2 portları (4444/1337/31337), Tor (9050/9051), yüksek veri transferi...
- **Registry (7):** Run key kalıcılığı, Windows Defender devre dışı, UAC bypass...
- **USB (3):** Büyük depolama cihazı, bilinmeyen sınıf, Rubber Ducky kalıbı...

---

## Gizlilik

Defense **hiçbir veriyi dışarıya göndermez.** Tüm analiz yerel cihazınızda gerçekleşir.

Alert çıktısında **bulunan**: süreç adları, PID'ler, dosya yolları, dış IP adresleri, zaman damgası.  
Alert çıktısında **bulunmayan**: dosya içerikleri, ağ trafiği içeriği, şifreler, kullanıcı adları, tarayıcı geçmişi, tuş vuruşları.

Detaylar için [PRIVACY.md](PRIVACY.md) dosyasına bakın.

---

## Log Paylaşımı (Opsiyonel)

Tespit ettiğiniz gerçek tehditleri toplulukla paylaşmak, kural setini iyileştirmemize yardımcı olur.

Paylaşmadan önce lütfen aşağıdakileri kontrol edin:
- Kullanıcı adı içeren yolları anonimleştirin (örn. `C:\Users\[USER]\...`)
- İç IP adreslerini çıkarın
- Paylaşmak istemediğiniz komut satırı argümanlarını silin

Paylaşım kanalları:
- **GitHub Discussion:** https://github.com/Defense-open/defense-open/discussions
- **Discord:** `#threats-found` kanalı

---

## Katkıda Bulunma

### Kural Katkısı

Yeni bir tehdit kalıbı tespit ettiniz? GitHub'da kural PR'ı açın:

1. `rules/` dizininde uygun `.toml` dosyasını düzenleyin
2. Kuralı tetikleyen örnek bir event ekleyin (kural test formatında)
3. PR başlığını `[Rule] KURAL-ID: Kural adı` formatında yazın

**Kabul edilen her kural PR'ı = 3 aylık Pro lisans** (ilerleyen sürümlerde).

### Kod Katkısı

```bash
git clone https://github.com/Defense-open/defense-open.git
cd defense-open
cargo test --all
cargo clippy --all-targets -- -D warnings
```

PR açmadan önce tüm testlerin ve clippy kontrolünün geçtiğinden emin olun.

Güvenlik açığı bildirimi için [SECURITY.md](SECURITY.md) dosyasına bakın.

---

## CI Durumu

[![CI](https://github.com/Defense-open/defense-open/actions/workflows/ci.yml/badge.svg)](https://github.com/Defense-open/defense-open/actions/workflows/ci.yml)

3 platform (Ubuntu, macOS, Windows) + cargo-audit + cargo-deny

---

## Lisans

MIT — detaylar için [LICENSE](LICENSE) dosyasına bakın.

Kural dosyaları (`rules/`) Apache 2.0 ile lisanslanmıştır.
