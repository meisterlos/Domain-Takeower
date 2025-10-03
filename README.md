# Domain Takeover Scanner

🔍 **White Hat Security Tool** - Domain Takeover Vulnerability Detection

## Özellikler

- **Kapsamlı Subdomain Keşfi**
  - Subfinder entegrasyonu
  - crt.sh API kullanımı
  - VirusTotal API desteği
  - DNS bruteforce saldırısı
  - Yaygın subdomain listesi ile tarama

- **Domain Takeover Zafiyet Tespiti**
  - GitHub Pages
  - AWS S3 Buckets
  - Netlify
  - Vercel
  - Heroku
  - Azure
  - Firebase
  - Google App Engine

- **Modern GUI Arayüzü**
  - Gerçek zamanlı sonuç görüntüleme
  - İlerleme çubuğu
  - Tabbed interface
  - Sonuç dışa aktarma

## Kurulum

```bash
# Gerekli paketleri yükle
pip install -r requirements.txt

# Subfinder'ı yükle (opsiyonel)
# https://github.com/projectdiscovery/subfinder
```

## Kullanım

```bash
python domain_takeover_scanner.py
```

## Güvenlik Uyarısı

⚠️ **Bu araç sadece etik hacking ve güvenlik testleri için kullanılmalıdır.**

- Sadece sahip olduğunuz domainler üzerinde test yapın
- Yetkisiz erişim yapmayın
- Yasal sorumluluğu kabul ediyorsunuz

## Özellikler

### Subdomain Keşfi Metodları

1. **Subfinder** - En güçlü subdomain keşif aracı
2. **crt.sh** - SSL sertifika şeffaflık kayıtları
3. **DNS Bruteforce** - Yaygın subdomain isimleri
4. **VirusTotal API** - Güvenlik veritabanı
5. **Common Wordlist** - Kapsamlı subdomain listesi

### Domain Takeover Tespiti

- **GitHub Pages**: `github.io` subdomainleri
- **AWS S3**: S3 bucket konfigürasyon hataları
- **Netlify**: Netlify subdomain konfigürasyonu
- **Vercel**: Vercel deployment hataları
- **Heroku**: Heroku app konfigürasyonu

### Sonuç Raporlama

- JSON formatında dışa aktarma
- Severity seviyelerine göre kategorilendirme
- Detaylı istatistikler
- Gerçek zamanlı log görüntüleme

## Lisans

Bu proje eğitim amaçlıdır. Sorumluluk kullanıcıya aittir.

## Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun
3. Commit yapın
4. Push yapın
5. Pull Request açın

## İletişim

White Hat Security Researcher
