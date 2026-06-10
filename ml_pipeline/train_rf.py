"""
Random Forest Model Eğitimi ve ONNX Dışa Aktarımı

generate_dataset.py tarafından oluşturulan veriseti ile bir RandomForest
modeli eğitir. Modeli ONNX formatına dönüştürerek panicscan-ml (Rust) 
crate'inde kullanılabilmesini sağlar.
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import skl2onnx
from skl2onnx.common.data_types import FloatTensorType

def main():
    print("1. Veriseti yükleniyor...")
    df = pd.read_csv("panicscan_dataset.csv")
    
    # Özellikler (X) ve Etiket (y)
    X = df.drop("label", axis=1).astype(float)
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("2. RandomForest Modeli eğitiliyor...")
    # n_estimators=50 ve max_depth=10: çok hızlı inferans ve küçük model boyutu için
    rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    print("3. Model test ediliyor...")
    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
    
    print("4. ONNX formatına dönüştürülüyor...")
    # Özellik sayısı kadar float32 girdisi tanımlıyoruz.
    # entropy, file_size_bytes, suspicious_imports_count, has_signature, is_packed (5 özellik)
    initial_type = [('float_input', FloatTensorType([None, X.shape[1]]))]
    onnx_model = skl2onnx.convert_sklearn(
        rf, 
        initial_types=initial_type,
        options={id(rf): {'zipmap': False}} # zipmap false: raw probability array dönmesi için
    )
    
    onnx_filename = "panicscan_rf.onnx"
    with open(onnx_filename, "wb") as f:
        f.write(onnx_model.SerializeToString())
        
    print(f"✅ Model başarıyla kaydedildi: {onnx_filename}")
    print(f"Bu dosyayı rust tarafında (crates/panicscan-ml/models/) kullanabilirsiniz.")

if __name__ == "__main__":
    main()
