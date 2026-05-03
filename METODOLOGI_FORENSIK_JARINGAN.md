# Metodologi forensik jaringan (cakupan penelitian)

Dokumen ini menyelaraskan **judul penelitian** (*investigasi forensik jaringan terhadap jejak serangan prompt injection pada aplikasi web berbasis AI, memakai analisis log dan bukti lalu lintas jaringan*) dengan **implementasi** di repositori ini. Untuk arsitektur pipeline dan skema dataset, lihat [DOKUMENTASI_PROYEK.md](DOKUMENTASI_PROYEK.md).

---

## 1. Definisi operasional “forensik jaringan” di penelitian ini

Dalam cakupan tesis, **forensik jaringan** tidak dimaksudkan sebagai audit infrastruktur operator (ISP, backbone) atau dekripsi TLS pihak ketiga tanpa kunci. Yang dimaksud adalah:

> **Investigasi jejak komunikasi pada jalur yang menghubungkan klien ke layanan aplikasi web ber-AI**, dengan bukti yang dapat direkonstruksi dari **(i) rekaman lalu lintas pada lapisan yang dapat diamati** (mis. HTTP pada loopback, atau aliran melalui proxy), dan **(ii) log aplikasi terstruktur** yang dikorelasikan dengan permintaan tersebut.

Serangan **prompt injection** pada kasus ini adalah **muatan teks** yang dikirim melalui mekanisme aplikasi (biasanya **POST** `application/json` ke `/chat`) dan oleh karena itu **melewati stack** TCP/IP dan HTTP seperti lalu lintas klien–server lainnya.

---

## 2. Model bukti berlapis

| Lapisan | Artefak tipikal | Fungsi forensik |
|--------|------------------|-----------------|
| **A — Log aplikasi** | `forensic_log.txt` (satu JSON per baris) | Metadata permintaan: waktu, `request_id`, IP klien menurut Flask, `user_agent`, panjang badan, klasifikasi respons. |
| **B — Lalu lintas jaringan** | Berkas `.pcap` (mis. `tcpdump`/`tshark`), dan/atau **access log** reverse proxy | Bukti transmisi: alamat sumber/tujuan, port, fragmen alur HTTP (method, path, status), waktu relatif sesi. |
| **C — Korelasi** | `request_id` (UUID) yang sama di: respons JSON `/chat`, baris log, serta (secara manual) diselaraskan dengan frame HTTP di Wireshark lewat **waktu** dan **isi POST** | Menautkan “paket/HTTP” ↔ “entri log” ↔ `hasil_serangan.json` / `injection_runs.jsonl`. |

**Skema dataset** (versi ≥ 1.2) menyertakan `request_id` per sampel agar rantai bukti dapat ditulis secara eksplisit di laporan.

---

## 3. Playbook: rekaman PCAP saat simulasi batch (lokal)

Prasyarat: `tcpdump` terpasang (biasanya sudah ada di Linux). Server Flask mendengarkan pada port **5001** (default kode).

**Terminal 1 — mulai capture sebelum batch:**

```bash
sudo tcpdump -i lo -w capture_batch.pcap 'tcp port 5001'
```

Atau skrip pembantu: [scripts/record_pcap_local.sh](scripts/record_pcap_local.sh).

*Catatan:* `lo` = loopback (sesuai `jalankan_serangan` memanggil `127.0.0.1:5001`). Jika klien mengakses hanya via ngrok dari host lain, sesuaikan **interface** (mis. `eth0`) dan **filter port** (port publik lokal ngrok).

**Terminal 2 — jalankan server + simulasi** seperti biasa (`python source_code_forensik.py` atau alur Colab).

**Setelah selesai:** hentikan `tcpdump` (Ctrl+C). Buka `capture_batch.pcap` di **Wireshark** atau:

```bash
tshark -r capture_batch.pcap -Y 'http.request.uri contains "/chat"' -T fields -e frame.time -e ip.src -e http.request.method -e http.request.uri
```

Korelasi: cari permintaan POST ke `/chat` pada **timestamp** yang berdekatan dengan baris `forensic_log.txt` (field `timestamp` dan `request_id`).

---

## 4. Google Colab dan PCAP

Colab sering membatasi `tcpdump` pada antarmuka tertentu. Opsi:

- Jalankan playbook PCAP pada **mesin lokal** Anda dengan kode yang sama, atau
- Gunakan sel opsional di `colab_forensik.ipynb` (jika `tcpdump` diizinkan) ke `/content/capture_batch.pcap`, lalu unduh berkasnya ke laptop untuk analisis Wireshark.

---

## 5. Bukti HTTP melalui reverse proxy (opsional)

Untuk menegaskan “lalu lintas HTTP” pada boundary server, aplikasi dapat diletakkan di balik **nginx** dengan **access log** format kustom. Lihat contoh konfigurasi: [scripts/nginx_forensik_example.conf](scripts/nginx_forensik_example.conf). Korelasi tetap memakai **waktu** + **request_id** di badan respons (disarankan juga mengecek body size di log vs `content_length` di log aplikasi).

---

## 6. Korpus serangan (dataset eksperimen)

Entri skenario disimpan di **[dataset_eksperimen.py](dataset_eksperimen.py)** sebagai daftar `SERANGAN` (impor di `source_code_forensik.py`). Pembaruan korpus dilakukan pada file tersebut agar ID stabil untuk reproduksi.

---

## 7. Pembatasan (disarankan untuk bab pembatasan tesis)

- Tidak ada dekripsi TLS end-to-end ke layanan eksternal; untuk demo **ngrok**, bukti “publik” adalah saluran yang Anda kendalikan ditambah artefak yang Anda rekam.
- Label BYPASS/Blocked bersifat **heuristik** (`dataset_confidence: heuristic_v1`).
- `request_id` tidak dimasukkan otomatis ke dalam muatan PCAP; **penyelarasan manual** dengan timestamp dan urutan batch adalah prosedur yang sah dalam metodologi deskriptif.
