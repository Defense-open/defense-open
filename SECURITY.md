# Güvenlik Politikası

## Kapsam

Bu politika aşağıdaki bileşenleri kapsar:

- `defense-agent` binary ve kaynak kodu
- `defense-core` kütüphanesi
- TOML kural motoru ve kural dosyaları
- CI/CD pipeline ve bağımlılıklar

## Güvenlik Açığı Bildirimi

**Lütfen güvenlik açıklarını kamuya açık GitHub Issue olarak paylaşmayın.**

### Bildirim Kanalı

GitHub'ın **Private Security Advisories** özelliğini kullanın:

1. Bu repo sayfasında **Security** sekmesine gidin
2. **"Report a vulnerability"** butonuna tıklayın
3. Formu doldurun

Alternatif olarak e-posta ile de iletişime geçebilirsiniz — e-posta adresini GitHub profilimizde bulabilirsiniz.

### Ne Beklemelisiniz

| Aşama | Süre |
|-------|------|
| Bildirimin alındığının onaylanması | 48 saat |
| İlk değerlendirme ve geri bildirim | 7 gün |
| Düzeltme hedefi (kritik açıklar) | 30 gün |
| Düzeltme hedefi (diğer açıklar) | 90 gün |

Düzeltme yayınlandıktan sonra, bildirimi yapan kişiyle mutabık kalınan süre sonunda açık kamuoyuyla paylaşılır (Coordinated Disclosure).

## Ödül

Şu an resmi bir bug bounty programımız yok. Ancak geçerli kritik bir güvenlik açığı bildirimi için **1 yıllık Pro lisans** sunuyoruz (ilerleyen sürümlerde geçerli olacak).

Geçerli sayılan bildirimler:
- Defense agent'ın kötüye kullanılmasına olanak tanıyan açıklar
- Kural motorunun atlatılmasını sağlayan açıklar
- Alert çıktısında veri sızıntısına yol açan açıklar
- Bağımlılıklarda kritik (CVSS ≥ 7.0) güvenlik açıkları

## Kapsam Dışı

- Teorik saldırılar (PoC olmadan)
- Defense'in çalıştığı işletim sistemindeki açıklar
- Defense'i kaldırıp kaldıramama (yönetici yetkisi ile her şey mümkün — bu bir sınırlama, açık değil)
- Sosyal mühendislik

## Güvenlik Anlayışımız

Defense, kullanıcı-alanı (user-space) bir araçtır. Ayrıcalıklı bir saldırgan Defense'i sonlandırabilir — bu tasarım gereği bir sınırlamadır ve dokümantasyonda açıkça belirtilmiştir. Kernel-level koruma (ELAM/eBPF) sonraki fazlarda planlanmaktadır.

Defense **hiçbir veriyi dışarıya göndermez.** Kaynak kod açık ve denetlenebilirdir.
