# Gizlilik Politikası

**Son güncelleme:** 2026-06-22

Defense, sıfır telemetri prensibiyle çalışır. Bu belge tam olarak neyin toplandığını ve neyin toplanmadığını açıklar.

---

## Ne Toplanır

Defense ajanı çalışırken aşağıdaki verileri **yerel cihazınızda** üretir ve saklar:

### Alert Çıktısı (alerts.jsonl veya stdout)

| Veri | Örnek |
|------|-------|
| Süreç adı ve tam yolu | `C:\Windows\System32\cmd.exe` |
| Komut satırı argümanları | `cmd.exe /c powershell -enc ...` |
| PID ve üst süreç bilgisi | `pid: 1234, parent: WINWORD.EXE` |
| Dosya yolu | `C:\Users\[USER]\AppData\Temp\evil.exe` |
| Ağ bağlantısı (hedef IP ve port) | `185.220.101.47:443` |
| Kayıt defteri anahtar yolu | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| USB cihaz sınıfı | `MassStorage` |
| Zaman damgası | `2026-06-22T14:30:00Z` |
| Tehdit skoru ve kural ID | `score: 85, rule: PROC-001` |

---

## Ne Toplanmaz

Defense aşağıdaki verileri **hiçbir zaman toplamaz veya işlemez:**

- Dosya içerikleri (okunmaz, analiz edilmez)
- Ağ trafiği içeriği (paket verisi, HTTP içeriği, şifreli veri)
- Şifreler veya kimlik bilgileri
- Kullanıcı adları (yalnızca dosya yollarında geçebilir)
- Tarayıcı geçmişi veya çerezler
- Tuş vuruşları (keylogger değildir)
- Ekran görüntüsü
- Coğrafi konum
- Donanım kimlik bilgileri (MAC adresi, seri numarası vb.)
- Lisans veya kullanım istatistikleri

---

## Veriler Nerede Saklanır

Tüm veriler **yalnızca yerel cihazınızda** saklanır:

- Alert çıktısı: `--alert-file` parametresiyle belirttiğiniz dosya veya terminal stdout
- Hiçbir veri otomatik olarak dışarıya gönderilmez
- Hiçbir bulut bağlantısı kurulmaz
- Hiçbir "phone home" mekanizması yoktur

Bunu doğrulamak için ağ trafiğini izleyebilir veya kaynak kodu inceleyebilirsiniz.

---

## Veri Paylaşımı

Defense **asla** verilerinizi üçüncü taraflarla paylaşmaz.

**Opsiyonel topluluk paylaşımı:** Tespit ettiğiniz tehditleri toplulukla paylaşmak isterseniz bu tamamen sizin inisiyatifinizde ve manueldir. Paylaşmadan önce hassas bilgileri (kullanıcı adı, iç IP adresi vb.) kaldırmanızı öneririz.

---

## Verilerinizi Silme

Defense'in ürettiği tüm verileri silmek için:

```bash
# Alert dosyasını sil (belirttiğiniz dosya)
rm alerts.jsonl

# Veya stdout kullanıyorsanız zaten yerel dosya üretilmez
```

Defense kurulumunu kaldırdığınızda hiçbir arka kapı, servis veya kalıcı veri kalmaz.

---

## Açık Kaynak Güvencesi

Defense tamamen açık kaynaklıdır. Bu gizlilik politikasındaki her iddia kaynak koddan doğrulanabilir:

- Dış ağ bağlantısı yok: `grep -r "reqwest\|ureq\|hyper" defense-core/src/` — hiçbir HTTP client bağımlılığı yok
- Dosya içeriği okunmuyor: Filesystem kolektörü yalnızca inotify/FSEvents/RDCW olaylarını dinler, dosya içeriğini okumaz

Herhangi bir endişeniz için [SECURITY.md](SECURITY.md) üzerinden bildirin.

---

## İletişim

Gizlilikle ilgili sorularınız için GitHub Discussions veya SECURITY.md'deki iletişim kanallarını kullanabilirsiniz.
