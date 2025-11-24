# MiniIDS - Basit Sızma Tespit Sistemi

Bu proje, Sızma belirleme konusundaki teorik bilgilere dayanarak hazırlanmış basit bir **Host-Based Intrusion Detection System (HIDS)** prototipidir.

## Özellikler

1.  **Dosya Bütünlük İzleme (File Integrity Monitoring):**
    *   `safe_zone` klasöründeki dosyaların SHA-256 hashlerini (parmak izlerini) alır.
    *   Dosya içeriği değiştiğinde, yeni dosya eklendiğinde veya silindiğinde uyarı verir.
    *   *İlgili Konu:* Rootkit tespiti, Hash kontrolü.

2.  **Süreç (Process) Anomali Tespiti:**
    *   Program başladığında çalışan süreçleri "güvenli" (baseline) olarak kabul eder.
    *   Sonradan başlayan her yeni süreci "anomali" olarak algılar ve bildirir.
    *   *İlgili Konu:* Şüpheli süreçleri inceleme.

3.  **Ağ Port İzleme:**
    *   Açık TCP portlarını izler.
    *   Yeni bir port dinlenmeye başlandığında (örneğin bir arka kapı/backdoor açıldığında) uyarır.
    *   *İlgili Konu:* Ağ bağlantılarını kontrol etme.

## Kurulum ve Çalıştırma

Bu uygulama Python 3 ile yazılmıştır ve ekstra bir kütüphane kurulumu gerektirmez (Linux standart araçlarını kullanır).

1.  MiniIDS dizinine gidin:
    ```bash
    cd MiniIDS
    ```

2.  Uygulamayı başlatın:
    ```bash
    python3 mini_ids.py
    ```

3.  **Test Etmek İçin (Saldırı Senaryoları Simülasyonu):**
    *   Uygulama çalışırken başka bir terminal açın.
    *   Aşağıdaki örnek komutları deneyerek MiniIDS'in tepkilerini gözlemleyin.
    *   MiniIDS ekranında **[UYARI]** mesajlarını ve `ids_log.txt` dosyasındaki kayıtları kontrol edin.

    ### A. Dosya Bütünlük İzleme Testleri:
    *(Bir saldırganın sisteme yeni dosya yüklemesi, mevcut kritik dosyaları değiştirmesi veya izlerini silmek için dosya silmesi senaryolarını simüle eder.)*

    *   **Yeni bir dosya oluşturma (Örn: Zararlı yazılım bırakma):**
        ```bash
        touch MiniIDS/safe_zone/zararli_yazilim.sh
        ```
    *   **Mevcut bir dosyayı değiştirme (Örn: Yapılandırma dosyası veya Rootkit):**
        ```bash
        echo "Saldırgan tarafından değiştirildi!" >> MiniIDS/safe_zone/kritik_veriler.txt
        ```
    *   **Bir dosyayı silme (Örn: Logları veya kanıtları silme):**
        ```bash
        rm MiniIDS/safe_zone/zararli_yazilim.sh
        ```

    ### B. Süreç Anomali Tespiti Testleri:
    *(Bir saldırganın sisteme sızdıktan sonra beklenmedik bir komut veya zararlı bir süreç başlatması senaryosunu simüle eder.)*

    *   **Bilinmeyen bir süreç başlatma (Örn: Ters kabuk veya bilgi toplama aracı):**
        ```bash
        # Örneğin, 10 saniye uyuyan bir süreç başlatma
        sleep 10 &
        # Veya basit bir netcat dinleyicisi başlatma (yönetici yetkisi gerekebilir)
        # nc -lvp 4444 & 
        ```

    ### C. Ağ Port İzleme Testleri:
    *(Bir saldırganın veya zararlı yazılımın sisteme arka kapı (backdoor) açmak için yeni bir portu dinlemeye başlaması senaryosunu simüle eder.)*

    *   **Yeni bir portu dinlemeye başlama (Örn: Backdoor):**
        ```bash
        # Netcat kullanarak basit bir dinleyici başlatma
        nc -lvp 12345 &
        ```

## Loglar

Tüm uyarılar `ids_log.txt` dosyasına kaydedilir.
