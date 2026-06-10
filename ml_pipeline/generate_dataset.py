"""
Sentetik Malware / Benign Veriseti Üretici

Bu betik, Rust panicscan-core tarafından bir dosyadan çıkartılabilecek statik
özellikleri (features) simüle ederek bir eğitim veriseti oluşturur.
Normalde bu özellikler LIEF veya kendi parserımız ile PE/ELF dosyalarından çıkarılır.

Özellikler (Features):
- entropy (float): Dosyanın Shannon entropisi (0.0 - 8.0). Şifrelenmiş veya paketlenmiş malware'lerde yüksektir (7.0+).
- file_size_bytes (int): Dosya boyutu.
- suspicious_imports_count (int): VirtualAlloc, LoadLibrary, GetProcAddress gibi tehlikeli API çağrı sayıları.
- has_signature (int): Dijital imza varsa 1, yoksa 0.
- is_packed (int): UPX, Themida vb. tespit edildiyse 1.

Etiket (Label):
- 1 = Malicious (Zararlı)
- 0 = Benign (Temiz)
"""

import pandas as pd
import numpy as np

def generate_dataset(num_samples=10000):
    np.random.seed(42)
    
    # 50% Benign, 50% Malicious
    num_benign = num_samples // 2
    num_malicious = num_samples - num_benign

    # --- BENIGN ÜRETİMİ ---
    # Normal dosyalar: Düşük/Orta entropi, genellikle imzalı, daha az şüpheli import, nadiren packed.
    benign_entropy = np.random.normal(loc=4.5, scale=1.0, size=num_benign).clip(0, 8)
    benign_size = np.random.lognormal(mean=12, sigma=1.5, size=num_benign).astype(int)
    benign_susp_imports = np.random.poisson(lam=2, size=num_benign)
    benign_sig = np.random.binomial(n=1, p=0.85, size=num_benign)
    benign_packed = np.random.binomial(n=1, p=0.05, size=num_benign)
    
    benign_df = pd.DataFrame({
        'entropy': benign_entropy,
        'file_size_bytes': benign_size,
        'suspicious_imports_count': benign_susp_imports,
        'has_signature': benign_sig,
        'is_packed': benign_packed,
        'label': 0
    })

    # --- MALICIOUS ÜRETİMİ ---
    # Zararlı dosyalar: Yüksek entropi (şifreli/packed), imzasız, çok şüpheli import.
    mal_entropy = np.random.normal(loc=7.2, scale=0.5, size=num_malicious).clip(0, 8)
    mal_size = np.random.lognormal(mean=11, sigma=2.0, size=num_malicious).astype(int)
    mal_susp_imports = np.random.poisson(lam=15, size=num_malicious)
    mal_sig = np.random.binomial(n=1, p=0.05, size=num_malicious)
    mal_packed = np.random.binomial(n=1, p=0.70, size=num_malicious)

    mal_df = pd.DataFrame({
        'entropy': mal_entropy,
        'file_size_bytes': mal_size,
        'suspicious_imports_count': mal_susp_imports,
        'has_signature': mal_sig,
        'is_packed': mal_packed,
        'label': 1
    })

    # Verisetini birleştir ve karıştır
    df = pd.concat([benign_df, mal_df]).sample(frac=1).reset_index(drop=True)
    
    return df

if __name__ == "__main__":
    df = generate_dataset(20000)
    df.to_csv("panicscan_dataset.csv", index=False)
    print(f"Dataset oluşturuldu: panicscan_dataset.csv ({len(df)} örnek)")
    print(df.head())
