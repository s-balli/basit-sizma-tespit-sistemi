import os
import time
import hashlib
import psutil
import datetime
import sys

# Konfigürasyon
WATCH_DIR = "./safe_zone" # Bütünlük kontrolü yapılacak dizin
POLL_INTERVAL = 5         # Kontrol aralığı (saniye)
LOG_FILE = "ids_log.txt"
HONEYPOT_FILE = "admin_passwords.txt" # Tuzak dosya adı

def log_alert(message, critical=False):
    """
    Uyarıları hem ekrana basar hem de dosyaya kaydeder.
    Konu-05: 'Bildirici' rolünü üstlenir.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if critical:
        prefix = "[!!! KRİTİK SALDIRI !!!]"
        color_code = "\033[41;97m" # Kırmızı Arkaplan, Beyaz Yazı (Daha dikkat çekici)
    else:
        prefix = "[UYARI]"
        color_code = "\033[91m" # Sadece Kırmızı Yazı

    formatted_msg = f"[{timestamp}] {prefix} {message}"
    print(f"{color_code}{formatted_msg}\033[0m") 
    
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
    psutil kütüphanesini kullanarak çalışan süreç isimlerini alır.
    Platform bağımsızdır (Windows/Linux/macOS).
    """
    processes = set()
    try:
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name']:
                    processes.add(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception as e:
        log_info(f"Süreç listesi alınırken hata: {e}")
    return processes

# --- 3. AĞ İZLEME (Network Monitoring) ---
# Konu-05: "Ağ Bağlantılarını Kontrol Etme"

def get_open_ports():
    """
    psutil ile dinlenen TCP portlarını alır.
    """
    ports = set()
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                ports.add(str(conn.laddr.port))
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        # Bazı sistemlerde tüm bağlantıları görmek için root yetkisi gerekebilir
        pass
    except Exception as e:
        log_info(f"Port listesi alınırken hata: {e}")
    return ports

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
            for filepath, file_hash in list(baseline_files.items()):
                is_honeypot = os.path.basename(filepath) == HONEYPOT_FILE
                
                if filepath not in current_files:
                    msg = f"DOSYA SİLİNDİ: {filepath}"
                    if is_honeypot:
                        log_alert(f"TUZAK DOSYA SİLİNDİ! SALDIRGAN İZLERİ SİLMEYE ÇALIŞIYOR OLABİLİR: {filepath}", critical=True)
                    else:
                        log_alert(msg)
                    del baseline_files[filepath]
                elif current_files[filepath] != file_hash:
                    msg = f"DOSYA BÜTÜNLÜĞÜ BOZULDU (Hash Değişimi): {filepath}"
                    if is_honeypot:
                         log_alert(f"TUZAK DOSYA DEĞİŞTİRİLDİ! SALDIRGAN YEMİ YUTTU: {filepath}", critical=True)
                    else:
                        log_alert(msg)
                    # Hash güncellenir ki sürekli aynı uyarıyı vermesin (opsiyonel)
                    baseline_files[filepath] = current_files[filepath]
            
            # Yeni Eklenen Dosyalar
            for filepath in current_files:
                if filepath not in baseline_files:
                    is_honeypot = os.path.basename(filepath) == HONEYPOT_FILE
                    # Honeypot sonradan geri eklenirse de uyarı verelim
                    if is_honeypot:
                        log_alert(f"TUZAK DOSYA TEKRAR OLUŞTURULDU: {filepath}", critical=True)
                    else:
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
