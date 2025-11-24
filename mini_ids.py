import os
import time
import hashlib
import subprocess
import datetime
import sys

# Konfigürasyon
WATCH_DIR = "./safe_zone" # Bütünlük kontrolü yapılacak dizin
POLL_INTERVAL = 5         # Kontrol aralığı (saniye)
LOG_FILE = "ids_log.txt"

def log_alert(message):
    """
    Uyarıları hem ekrana basar hem de dosyaya kaydeder.
    Konu-05: 'Bildirici' rolünü üstlenir.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] [UYARI] {message}"
    print(f"\033[91m{formatted_msg}\033[0m") # Kırmızı renkli çıktı
    
    with open(LOG_FILE, "a") as f:
        f.write(formatted_msg + "\n")

def log_info(message):
    """
    Bilgilendirme mesajları.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [BİLGİ] {message}")

# --- 1. DOSYA BÜTÜNLÜK KONTROLÜ (File Integrity Monitoring) ---
# Konu-05: "Rootkit nasıl tespit edilir?" (Hash kontrolü)

def calculate_file_hash(filepath):
    """Bir dosyanın SHA-256 hash değerini hesaplar."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Dosyayı parça parça oku (büyük dosyalar için bellek dostu)
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

def get_dir_snapshot(directory):
    """Dizindeki tüm dosyaların {dosya_yolu: hash} haritasını çıkarır."""
    snapshot = {}
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_file_hash(filepath)
            if file_hash:
                snapshot[filepath] = file_hash
    return snapshot

# --- 2. SÜREÇ İZLEME (Process Monitoring) ---
# Konu-05: "Şüpheli Süreçleri İnceleme" ve "Anomali Modeli"

def get_running_processes():
    """
    Linux 'ps' komutunu kullanarak çalışan süreç isimlerini alır.
    Not: Standart kütüphane kullanarak bağımlılık yaratmamak için subprocess kullanıyoruz.
    """
    try:
        # ps -e -o comm= (Sadece komut isimlerini listeler)
        output = subprocess.check_output(["ps", "-e", "-o", "comm="], text=True)
        processes = set(output.strip().split('\n'))
        return processes
    except subprocess.CalledProcessError:
        return set()

# --- 3. AĞ İZLEME (Network Monitoring) ---
# Konu-05: "Ağ Bağlantılarını Kontrol Etme"

def get_open_ports():
    """
    'ss' (socket statistics) komutu ile dinlenen TCP portlarını alır.
    """
    try:
        # ss -tuln (TCP, UDP, Listening, Numeric)
        output = subprocess.check_output(["ss", "-tuln"], text=True)
        ports = set()
        lines = output.strip().split('\n')
        # İlk satır başlık olduğu için atlıyoruz
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 5:
                # Local Address:Port (örn: 127.0.0.1:8080 veya *:22)
                local_addr = parts[4]
                if ':' in local_addr:
                    port = local_addr.split(':')[-1]
                    ports.add(port)
        return ports
    except FileNotFoundError:
        return set(["Hata: 'ss' komutu bulunamadı"])
    except Exception as e:
        return set()

# --- ANA MOTOR (Main Engine) ---
# Konu-05: "Yönetici" ve "Ajan" mimarisi

def main():
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)
        log_info(f"İzlenecek dizin oluşturuldu: {WATCH_DIR}")
        log_info("Test için bu dizine dosya ekleyebilir veya değiştirebilirsiniz.")

    log_info("MiniIDS Başlatılıyor...")
    log_info("Temel Sızma Belirleme Modeli: Anomali Tespiti (Baseline Comparison)")
    
    # 1. Temel Çizgiyi (Baseline) Oluştur
    log_info("Sistem 'Normal' durumu öğreniliyor (Baseline oluşturuluyor)...")
    baseline_files = get_dir_snapshot(WATCH_DIR)
    baseline_processes = get_running_processes()
    baseline_ports = get_open_ports()
    
    log_info(f"İzlenen Dosya Sayısı: {len(baseline_files)}")
    log_info(f"Çalışan Süreç Sayısı: {len(baseline_processes)}")
    log_info(f"Açık Portlar: {', '.join(baseline_ports)}")
    log_info("İzleme başladı. Çıkmak için Ctrl+C'ye basın.")
    print("-" * 50)

    try:
        while True:
            time.sleep(POLL_INTERVAL)
            
            # --- A. Dosya Kontrolü ---
            current_files = get_dir_snapshot(WATCH_DIR)
            
            # Değişen veya Silinen Dosyalar
            for filepath, file_hash in baseline_files.items():
                if filepath not in current_files:
                    log_alert(f"DOSYA SİLİNDİ: {filepath}")
                elif current_files[filepath] != file_hash:
                    log_alert(f"DOSYA BÜTÜNLÜĞÜ BOZULDU (Hash Değişimi): {filepath}")
                    # Hash güncellenir ki sürekli aynı uyarıyı vermesin (opsiyonel)
                    baseline_files[filepath] = current_files[filepath]
            
            # Yeni Eklenen Dosyalar
            for filepath in current_files:
                if filepath not in baseline_files:
                    log_alert(f"YENİ DOSYA TESPİT EDİLDİ: {filepath}")
                    baseline_files[filepath] = current_files[filepath]

            # --- B. Süreç Kontrolü ---
            current_processes = get_running_processes()
            new_procs = current_processes - baseline_processes
            if new_procs:
                log_alert(f"BİLİNMEYEN SÜREÇ BAŞLATILDI: {', '.join(new_procs)}")
                baseline_processes.update(new_procs) # Yeni süreci tanıdık olarak ekle

            # --- C. Ağ Kontrolü ---
            current_ports = get_open_ports()
            new_ports = current_ports - baseline_ports
            if new_ports:
                log_alert(f"YENİ PORT DİNLENMEYE BAŞLANDI: {', '.join(new_ports)}")
                baseline_ports.update(new_ports)

    except KeyboardInterrupt:
        print("\nMiniIDS durduruldu.")

if __name__ == "__main__":
    main()
