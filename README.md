# Defense (Açık Kaynak Kodlu Kalkan)

Defense, klasik anlamda bir "tarayıcı (scanner)" DEĞİLDİR. 

**Çalışma Prensibimiz:**
Biz tarama yapıyorsak da bunu sadece program ilk çift tıklanıp açıldığında, bilgisayarda halihazırda aktif bir zararlı olup olmadığını tespit etmek için (kök-analiz) yaparız. 
Bunun haricindeki asıl amacımız ve vizyonumuz; arka planda 7/24 sessizce çalışarak **tamamen dışarıdan gelen tehditleri** anında tespit etmek ve kullanıcı onayıyla karantinaya almak veya silmektir.

**Dışarıdan Gelen Tehditler Şunlardır:**
- İnternetten yeni indirilen şüpheli dosyalar
- Güvensiz Wi-Fi ağlarına bağlanma ve Wi-Fi atakları (Evil Twin vb.)
- Zararlı Bluetooth bağlantı ve eşleşme istekleri (Bluesnarfing vb.)
- Bilgisayara dışarıdan bağlanan zararlı USB bellekler
- Zararlı ağ trafiği ve bağlantılar (Örn: DDoS saldırıları veya C2 sunucu bağlantıları)

*Tehdit = Sadece dosya demek DEĞİLDİR! Ağdan gelen bir sinyal, deauth paketi veya ddos atağı da bir tehdittir.*

Defense bu tehditleri (dosya olsun veya olmasın) anında yakalar, derinlemesine analiz eder ve yapay zeka (LLM ve P2P ağı) desteğiyle sana sade bir dille raporlayıp ne yapmak istediğini sorar.

---
## Kurulum (Son Kullanıcılar İçin)
1. [Releases](https://github.com/defense-open/defense-open/releases) sayfasına gidin.
2. İşletim sisteminize uygun olan sürümü indirin.
3. Çift tıklayarak çalıştırın. Başlangıçta bir kez sistemi hızlıca analiz edecek ve ardından sonsuza dek dış yüzey tehditlerine karşı (Wi-Fi, USB, Bluetooth, İndirmeler) kalkan görevini üstlenecektir.

---
## Geliştiriciler İçin Testler (Yerel Performans Analizi)
Arka plandaki izleme sistemimizin kararlılığını test etmek için `tests/` klasöründeki betikleri kullanabilirsiniz. Performans testleri hız odaklı değil, sistemi ve RAM'i ne kadar az yorduğu (maks. 300MB) odaklıdır.
