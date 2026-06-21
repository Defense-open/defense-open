# Defense XDR — Geliştirme Kontrol Noktaları

Bu dosya tamamlanan fazları, yapılan teknik kararları ve mevcut durumu belgelemektedir.

---

## Faz 0 — Temel Altyapı (Hafta 1–2) ✅

### Yapılanlar

**Rust Workspace**
- `defense-core` (kütüphane) + `defense-agent` (binary) iki crate'li workspace kuruldu
- `edition = "2021"`, `resolver = "2"`

**Trait İskeleti (`defense-core`)**
- `SecurityEvent` — tüm event türlerini kapsayan enum (`Process`, `FileSystem`, `Network`, `Registry`, `Usb`)
- `Collector` trait — async, `Send + Sync`, `name()` + `run(tx)` arayüzü
- `EventBus` — Tokio mpsc kanalı üzerine kurulu; collector'lar `sender()` ile yazar, ana döngü `recv()` ile okur
- `RuleEngine` trait — `evaluate(&SecurityEvent) -> Vec<RuleMatch>`
- `EventSink` trait — `handle(&SecurityEvent, &[RuleMatch])`

**Log Sistemi**
- `log.rs`: `Level` enum (Info/Medium/High/Critical), `format_log_line`, path masking (`/home/[USER]/`, `C:\Users\[USER]\`)
- `log_rotation.rs`: `RotatingLog` — 10 MB aşılınca `.txt.gz` arşivi oluşturur, yeni dosya başlatır; `flate2` ile gzip sıkıştırma; harici bağımlılık olmadan Gregorian takvim hesabı

**CI Pipeline (`.github/workflows/ci.yml`)**
- 3 platform: `ubuntu-latest`, `macos-latest`, `windows-latest`
- `cargo fmt --check` + `cargo clippy -D warnings` + `cargo test --locked`
- `cargo-audit --deny unsound --deny yanked` (CVSS ≥7.0 ve yanked crate'ler CI'yi kırar; unmaintained uyarıları geçer)
- `cargo-deny` — lisans kontrolü (`MIT`, `Apache-2.0`, `BSD-*`, `ISC`, `Unicode-3.0`, `CC0-1.0`, `Zlib`)
- Haftalık zamanlanmış tarama (her Pazartesi 08:00 UTC)

**Test Durumu:** 11 test, hepsi yeşil

### CI Sorunları ve Çözümleri
| Sorun | Çözüm |
|-------|-------|
| `rustsec/audit-check@v2` deprecated | `cargo install cargo-audit` + doğrudan CLI |
| `Cargo.lock` eksik | Commit'e eklendi (binary crate için zorunlu) |
| `deny.toml`: `copyleft`/`deny` anahtarları kaldırılmış | cargo-deny v0.14+ sözdizimine güncellendi |
| `Unicode-DFS-2016` yanlış, `Unicode-3.0` gerekli | `unicode-ident` crate'inin gerçek lisansı eklendi |
| `CC0-1.0` eksik | `notify` bağımlılığı için eklendi |
| `instant` unmaintained uyarısı | `--deny warnings` → `--deny unsound --deny yanked` |
| macOS/Linux'ta unused import (`registry.rs`) | Import'lar `#[cfg(windows)]` bloğuna taşındı |

---

## Faz 1 — Kural Motoru Çekirdeği (Hafta 3–6) ✅

### 5 Collector

| Collector | Yöntem | Platform |
|-----------|--------|----------|
| `ProcessCollector` | `sysinfo 0.33` polling, yeni PID'leri takip eder | Tüm platformlar |
| `FileSystemCollector` | `notify 7` crate, inotify/FSEvents/ReadDirectoryChanges | Tüm platformlar |
| `NetworkCollector` | `sysinfo` interface istatistikleri + `/proc/net/tcp` (Linux) | Tüm platformlar |
| `RegistryCollector` | `winreg` ile Run/Winlogon/Services key snapshot karşılaştırması | Sadece Windows |
| `UsbCollector` | `sysinfo::Disks`, `is_removable()` ile çıkarılabilir disk tespiti | Tüm platformlar |

### TOML Kural Motoru

- `TomlRuleEngine`: kural dosyalarını `rules/` dizininden yükler
- Koşul operatörleri: `contains`, `not_contains`, `equals`, `not_equals`, `starts_with`, `ends_with`, `gt`, `lt`, `eq`
- Eşleşme modu: `match_mode = "all"` (AND) veya `match_mode = "any"` (OR)
- Tüm karşılaştırmalar case-insensitive
- Field yolu: `process.image`, `process.command_line`, `fs.path`, `fs.event_type`, `network.dst_port`, `registry.key`, `usb.device_class` vb.

### 50 Kural

| Dosya | Kural Sayısı | Örnek |
|-------|-------------|-------|
| `rules/process.toml` | 15 | PowerShell Encoded Command, Mimikatz, Shadow Copy Silme |
| `rules/filesystem.toml` | 15 | Ransomware uzantısı, LSASS dump, Startup folder |
| `rules/network.toml` | 10 | C2 portları, Tor, yüksek exfiltration |
| `rules/registry.toml` | 7 | Run key, Winlogon, Defender devre dışı |
| `rules/usb.toml` | 3 | Mass storage, bilinmeyen sınıf |

Tüm kurallar MITRE ATT&CK teknik ID'leriyle etiketlidir ve `recommended_action` içerir.

---

## Faz 2 — Community MVP Agent Runtime (Hafta 7–9) ✅

### Agent Runtime (`defense-agent`)

**CLI (Clap)**
```
defense-agent [OPTIONS]

Options:
  --rules-dir <PATH>       Kural TOML dizini [varsayılan: rules]
  --alert-file <PATH>      Alert çıktı dosyası [varsayılan: stdout]
  --buffer <N>             EventBus tampon boyutu [varsayılan: 1024]
  --collectors <LIST>      Aktif collector'lar [varsayılan: process,fs,network,registry,usb]
```

**Event Loop**
1. Kural motoru `--rules-dir`'den yüklenir
2. Her collector ayrı Tokio task'inde spawn edilir
3. Tüm collector'lar aynı `EventBus`'a yazar
4. Ana döngü event alır → kural motoruna geçirir → eşleşme varsa alert yayar
5. `Ctrl+C` / `SIGTERM` → graceful shutdown, tüm task'ler abort edilir

**JSON Alert Formatı**
```json
{
  "timestamp": "2026-06-21T22:21:40Z",
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

**Gerçek platform testi:** Çalıştırıldığında sistem process'leri anında tespit etti, JSON alert'ler stdout'a aktı.

---

## Mevcut Durum

**Repo:** [Defense-open/defense-open](https://github.com/Defense-open/defense-open)  
**CI:** Tüm platformlarda yeşil ✅  
**Son commit:** `fix: cargo-audit`

### Bağımlılık Özeti

| Crate | Amaç |
|-------|------|
| `tokio` | Async runtime |
| `async-trait` | Async trait desteği |
| `serde` / `serde_json` | Serialization |
| `toml` | Kural dosyası parse |
| `regex` | Log path masking |
| `flate2` | Log rotation gzip |
| `sysinfo` | Process/disk/network bilgisi |
| `notify` | Filesystem event izleme |
| `winreg` | Windows registry (Windows only) |
| `clap` | CLI argüman parse |
| `chrono` | Alert timestamp |

---

## Sıradaki: Faz 3 — Community Döngüsü (Hafta 10–16)

- [ ] README.md — kurulum, kullanım, katkı rehberi
- [ ] `cargo install defense-agent` talimatları ve crates.io yayını
- [ ] Show HN / Reddit /r/netsec lansmanı
- [ ] Honeypot altyapısı (Cowrie SSH + Dionaea)
- [ ] Kural kalitesi iyileştirmesi (false positive azaltma)
- [ ] Hedef: 200+ GitHub star, 50+ aktif kullanıcı
