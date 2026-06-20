# 🔍 Network Port Scanner (Eğitim Amaçlı)

Çok iş parçacıklı (multi-threaded) basit bir TCP port tarayıcı. Ağ
yönetimi öğrenmek, kendi sunucularınızı denetlemek veya temel ağ
programlama kavramlarını (soket, threading) anlamak için tasarlanmıştır.

## ⚠️ Yasal Uyarı

**Bu aracı SADECE kendi sahip olduğunuz veya tarama izniniz olan
sistemlerde/ağlarda kullanın** (kendi ev ağınız, localhost, kendi
sunucularınız, CTF/lab ortamları). İzinsiz port taraması birçok ülkede
yasalara aykırıdır ve yetkisiz erişim girişimi olarak
değerlendirilebilir. Bu proje tamamen **eğitim ve ağ yönetimi**
amaçlıdır; sorumluluk tamamen kullanıcıya aittir.

Araç, özel/yerel olmayan (yani genel internet) adresler için varsayılan
olarak çalışmayı reddeder; bunu aşmak isteyen kullanıcı bilinçli olarak
`--i-have-permission` bayrağını eklemelidir.

## Özellikler

- ⚡ Çok iş parçacıklı tarama (varsayılan 50 thread, ayarlanabilir)
- 📋 25+ yaygın servisin otomatik tanınması (SSH, HTTP, MySQL, RDP, vb.)
- 🎯 Tekil port, liste veya aralık belirtme desteği (`22,80` veya `1-1024`)
- 🛑 Genel internet adresleri için yerleşik güvenlik kontrolü
- 🚫 Harici bağımlılık yok, sadece Python standart kütüphanesi

## Kurulum

Sadece Python standart kütüphanesi kullanılır, kurulum gerekmez.

## Kullanım

```bash
# Kendi yerel ağınızdaki bir cihazı yaygın portlar için tara
python3 port_scanner.py 192.168.1.1

# Belirli bir port aralığı
python3 port_scanner.py localhost --ports 1-1024

# Belirli portlar
python3 port_scanner.py 192.168.1.1 --ports 22,80,443,3306

# Daha hızlı tarama için thread sayısını artır
python3 port_scanner.py 192.168.1.1 --threads 150 --timeout 0.5

# Kendi sunucunuz gibi genel bir adres (izniniz olduğunu onaylayarak)
python3 port_scanner.py sizin-kendi-sunucunuz.com --i-have-permission
```

| Parametre | Açıklama | Varsayılan |
|---|---|---|
| `host` | Hedef IP/hostname (zorunlu) | — |
| `--ports` | Port listesi/aralığı | yaygın 25 port |
| `--threads` | Eşzamanlı iş parçacığı sayısı | 50 |
| `--timeout` | Bağlantı zaman aşımı (saniye) | 1.0 |
| `--i-have-permission` | Genel adresler için izin onayı | gerekli (yerel olmayanlar için) |

## Nasıl çalışır?

Her port için bir TCP "connect scan" yapılır: `socket.connect_ex()` ile
bağlantı denenir, dönen sonuç koda göre portun açık olup olmadığı
belirlenir. İşlem, bir `Queue` üzerinden paylaşılan port listesini
tüketen birden fazla worker thread ile paralelleştirilir, bu da büyük
port aralıklarının taranmasını önemli ölçüde hızlandırır.

## Lisans

MIT — eğitim amaçlı kullanım için. Kötüye kullanım yazarın
sorumluluğunda değildir.


---

> Made in [discord.gg/codeshare](https://discord.gg/codeshare) · [astra-dev.com.tr](https://astra-dev.com.tr)
