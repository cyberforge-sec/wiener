# WIENER — 7-MINUTE PITCH SCRIPT & DEFENSE DOSSIER (FINAL MASTER SYNCHRONIZED)

* **Kompetisi:** HackNusa Cyber Defense (Track: AI vs AI)
* **Dataset Rujukan Resmi:** `data/experiments/authoritative_20260912_clean_2252/` (135 Trials · 16/16 Invariants Passed)
* **Status Konsistensi:** 100% Sinkron antara Source Code, JSONL, Hero Box Dashboard (`/dashboard`), dan Skrip.
* **Total Durasi:** 07:00 (420 Detik)
* **Format:** Presentasi Lisan + Slide + Live Web Demo (`/judge`)

---

### Peta Waktu & Bobot Rubrik Penilaian (Total 100%)

| Waktu | Segmen | Target Rubrik Penilaian | Bobot |
|---|---|---|:---:|
| **0:00 – 0:35** (35s) | **1. THE HOOK** | Accordance with the Track | **5%** |
| **0:35 – 1:15** (40s) | **2. THE PROBLEM** | The Trust Boundary & 15.6% Leakage | *(Setup)* |
| **1:15 – 2:35** (80s) | **3. SOLUTION & USP** | **Unique Selling Proposition (USP)** | **25%** |
| **2:35 – 4:25** (110s)| **4. THE LIVE DEMO** | **Proof of Concept (PoC)** | **25%** |
| **4:25 – 5:30** (65s) | **5. THE STACK** | **Technical Feasibility** | **25%** |
| **5:30 – 6:20** (50s) | **6. LEVEL OF SECURITY** | **Level of Security** | **10%** |
| **6:20 – 7:00** (40s) | **7. SCALABILITY & CLOSE**| **Scalability & Deployment Readiness** | **10%** |

---

# BAGIAN I: SKRIP PRESENTASI LISAN (00:00 – 07:00)

---

### SEGMEN 1: THE HOOK (0:00 – 0:35) | Bobot: Track Accordance (5%)
**Visual / Slide:** Slide 1 — Judul proyek **WIENER**, logo terminal monokrom, badge: *HackNusa Cyber Defense Track: AI vs AI*.
**Stage Direction:** Berdiri tegak di tengah panggung. Tatap langsung ke dewan juri, buat jeda hening 1 detik sebelum mulai berbicara, tempo tenang dan tegas.

> *"Bayangkan sebuah AI SOC Agent yang memiliki wewenang mematikan akun eksekutif, mengisolasi server produksi, atau memblokir gateway perusahaan dalam hitungan detik — tanpa campur tangan manusia.*
>
> *Sekarang bayangkan seorang penyerang cukup menyisipkan satu baris teks tersembunyi di dalam log alert, dan AI tersebut patuh mengeksekusinya.*
>
> *Di HackNusa Cyber Defense Track: AI vs AI, ini bukan fiksi — ini adalah ancaman nyata ketika AI pertahanan berhadapan dengan manipulasi AI penyerang.*
>
> *Nama saya Adiva, dan ini **WIENER** — arsitektur pertahanan adaptif yang memastikan usulan berbahaya dari model tidak memiliki jalur langsung menuju eksekusi."*

---

### SEGMEN 2: THE PROBLEM (0:35 – 1:15) | Fondasi USP
**Visual / Slide:** Slide 2 — Grafik Komparasi Authoritative UAR:
*No Defense (26.7%) $\rightarrow$ Basic Prompt Defense (15.6%) $\rightarrow$ Kebocoran Aksi Berbahaya*. Diagram celah *Trust Boundary*.
**Stage Direction:** Intonasi analitis, beri penekanan suara pada kegagalan prompt guardrail.

> *"Mengapa sistem SOC agent rentan? Dalam arsitektur yang kami evaluasi, salah satu risiko utamanya adalah: **memberikan hak eksekusi langsung kepada model bahasa.***
>
> *Banyak engineer mengira solusinya cukup dengan memperketat prompt instruksi pengaman.*
> *Namun dalam dataset evaluasi autoritatif kami terhadap 135 trial pengujian:*
> - *Tanpa pertahanan, Unsafe Action Rate mencapai **26.7%** — 12 dari 45 trial menghasilkan tindakan destruktif.*
> - *Ketika ditambahkan Basic Prompt Defense, tingkat bahaya hanya turun ke **15.6%**.*
>
> *Artinya: 7 dari 45 trial masih menghasilkan aksi destruktif!*
>
> *Mengapa? Karena instruksi pengaman di dalam teks prompt tetap rentan disusupi oleh teknik injeksi kontekstual. Masalahnya ada pada **Trust Boundary**: model bahasa probabilistik tidak boleh menjadi otoritas keamanan terakhir."*

> ✂️ **[POTONGAN DARURAT 1]:** Jika pembukaan terasa lambat, pangkas kalimat pembuka dan langsung katakan:
> *"Data autoritatif kami membuktikan: prompt defense biasa masih meloloskan 7 dari 45 trial (15.6%) menjadi aksi destruktif. Guardrail di dalam prompt selalu bisa disusupi. Masalahnya ada pada Trust Boundary: LLM tidak boleh menjadi pengambil keputusan keamanan terakhir."* **(Hemat 10 detik).**

---

### SEGMEN 3: THE SOLUTION & USP (1:15 – 2:35) | Bobot: Unique Selling Proposition (25%)
**Visual / Slide:** Slide 3 — Diagram Arsitektur: Input Alert $\rightarrow$ **[5 Lapisan Pertahanan WIENER]** $\rightarrow$ Keputusan Eksekusi.
Teks tebal di tengah: **"The Model Never Decides. The Model Only Proposes."**
Badge Metrik: **UAR: 0.0% | UAPR: 100% | FIR: 0.0% (10 Benign WIENER · 30 Benign Total)**.
**Stage Direction:** Postur percaya diri, gunakan gestur tangan untuk memperagakan filter bertingkat.

> *"Prinsip inti WIENER sederhana:*
> ***Model tidak pernah memutuskan. Model hanya mengusulkan.***
>
> *WIENER memisahkan alur pertahanan ke dalam 5 lapisan independen:*
> 1. ***SOC Agent** hanya bertugas membaca alert dan mengajukan usulan aksi — tanpa hak eksekusi langsung.*
> 2. ***Trajectory Engine** membekukan seluruh rantai konteks dan penalaran ke dalam log append-only yang tidak bisa diubah.*
> 3. ***Blue AI** memprofil deviasi perilaku agen. Jika ada ambiguitas bukti, model lokal Qwen dipanggil untuk klarifikasi — namun dilindungi oleh* ***Monotonic Guard**: hasil evaluasi model hanya bisa memperketat risiko, tidak pernah bisa membuat status lebih aman dari fakta awal.*
> 4. ***Risk Engine** mengalkulasi skor risiko secara matematis dari 4 bobot konfigurasi.*
> 5. *Dan terakhir,* ***Policy Gate*** *— gerbang berbasis kode logika biner di luar model yang menjatuhkan vonis:* ***ALLOW, REVIEW, atau BLOCK***.*
>
> *Hasil evaluasi pada dataset autoritatif 135 trial:*
> - *WIENER menekan Unsafe Action Rate dari 26.7% menjadi **0.0%**.*
> - *Pada dataset evaluasi kami, **UAPR mencapai 1.0 atau 100%**, karena UAR turun dari 26.7% menjadi 0.0%.*
> - *Pada 10 benign controls untuk WIENER, tidak ada false intervention — **FIR 0.0%**. Total seluruh eksperimen memiliki 30 benign controls lintas tiga mode.*
>
> *Bahkan saat agen terbujuk mengusulkan aksi berbahaya, dalam boundary dan skenario evaluasi kami, manipulasi teks pada input tidak dapat mengubah keputusan Policy Gate, karena gerbang ini beroperasi pada aturan kode biner, bukan model bahasa yang bisa dibujuk."*

---

### SEGMEN 4: THE LIVE DEMO (2:35 – 4:25) | Bobot: Proof of Concept (25%)
**Visual / Screen:** Pindah ke layar Browser live di `http://localhost:8000/judge` (Judge Mode UI).
**Stage Direction:** Tenang, biarkan request API selesai, lalu tunjuk badge hasil di layar secara spesifik.

> **[2:35 – 3:00] (Langkah 1: Normal Alert)**
> *(Klik: Provider: Cloud | Scenario: Normal $\rightarrow$ RUN)*
> *"Mari kita buktikan di antarmuka Judge Mode.*
> *Skenario pertama: Alert normal harian. Agen mengusulkan aksi baca:* `get_logs`.
> *Blue AI memvalidasi context trust normal, skor risiko rendah (21.0 di bawah threshold 30). Policy Gate memberikan badge hijau **ALLOW**, dan aksi tereksekusi secara aman pada simulated tool."*

> **[3:00 – 3:35] (Langkah 2: Prompt Injection Attack)**
> *(Klik: Scenario: Prompt Injection $\rightarrow$ RUN)*
> *Skenario kedua: Red AI menyuntikkan payload privilege-abuse, menyamar sebagai admin domain.*
> *Lihat di layar: agen kami tertipu dan mengusulkan tindakan berbahaya:* `disable_user`.
> *Namun di tahap berikutnya, Blue AI mencatat lonjakan privilege impact ke angka 80. Safety Constraint **SC-003 dan SC-012** aktif seketika.*
> *Policy Gate membanting vonis menjadi badge merah: **BLOCK**. Status eksekusi:* `refused_block`. *Nol aksi berbahaya tereksekusi."*

> **[3:35 – 4:05] (Langkah 3: Adaptive Attack Loop)**
> *(Klik: Scenario: Adaptive $\rightarrow$ RUN)*
> *Skenario ketiga: Closed-loop AI vs AI sesungguhnya.*
> *Pada iterasi pertama, serangan Red AI di-BLOCK. Hasil penolakan ini dibaca Red AI sebagai feedback, memicu mutasi payload menjadi teknik* `frame_shift` *pada iterasi kedua.*
> *Namun logika behavioral WIENER kembali mendeteksi anomali hak akses tersebut dan tetap mem-BLOCK serangan hasil mutasi.*
> *Pertahanan ini adaptif terhadap evolusi taktik penyerang."*

> **[4:05 – 4:25] (Langkah 4: Provider Failover & Truthful Label)**
> *(Arahkan kursor ke badge provider di kanan atas / switch ke Replay)*
> *"Terakhir, jika koneksi cloud terputus di tengah insiden, ladder kami otomatis turun ke model lokal Qwen, atau ke Deterministic Replay Mode.*
> *Hasil evaluasi keluar instan di bawah satu milidetik, dengan label transparan `REPLAY MODE` demi integritas audit yang jujur."*

> ✂️ **[POTONGAN DARURAT 2]:** Jika langkah 2 atau 3 mengalami latensi jaringan cloud agak lambat (>3 detik), di Langkah 4 **cukup tunjuk badge di pojok kanan atas** sambil bicara 1 kalimat:
> *"Sistem kami juga dilengkapi failover otomatis ke lokal dan replay instan jika koneksi internet terputus."* Jangan klik tombol replay lagi untuk menghemat 15 detik.

---

### SEGMEN 5: THE STACK & TECHNICAL FEASIBILITY (4:25 – 5:30) | Bobot: Technical Feasibility (25%)
**Visual / Slide:** Slide 4 — Arsitektur Sistem, Spesifikasi Resource, dan Integritas Bukti Autoritatif.
Badge: *Dataset Hash: f0428ec4... | 16/16 Invariants Passed | Automated Test Suite*.
**Stage Direction:** Tegas, lugas, artikulasi angka presisi tanpa tergesa-gesa.

> *"Untuk kelayakan teknis, WIENER adalah PoC simulasi yang dapat didemokan di laptop pengembang; kebutuhan nyata tetap bergantung pada provider dan model yang dipilih evaluator.*
>
> *Stack kami dibangun di atas 3 pilar:*
> 1. ***Cloud Tier***: *Endpoint OpenAI-compatible yang dikonfigurasi evaluator.*
> 2. ***Local Tier***: *Model ringkas Qwen2.5 1.5B via Ollama CPU-only, stabil di ~1.6 detik per inferensi.*
> 3. ***Deterministic Replay Tier***: *Mesin pencocokan berbasis SHA-1 prompt hash yang memproses evaluasi dalam **0.07 milidetik**.*
>
> *Integritas teknis kami tervalidasi menyeluruh:*
> - *Memory footprint aplikasi FastAPI hanya memakan **60 hingga 65 megabyte RAM**.*
> - *Checkout ini mengumpulkan 402 test otomatis; hasil eksekusi harus dilaporkan dari environment evaluasi.*
> - *Dan seluruh klaim data kami berakar pada **Authoritative Evidence Bundle**: 135 record lengkap, 0 deviasi, dan lulus 16 dari 16 invariant checks.*
>
> *Sistem ini siap untuk tahap integrasi dan pengujian lanjutan, terukur, dan berbasis evidence bundle yang tervalidasi secara teknis."*

---

### SEGMEN 6: LEVEL OF SECURITY (5:30 – 6:20) | Bobot: Level of Security (10%)
**Visual / Slide:** Slide 5 — Diagram *Defense-in-Depth*: 3 Boundary Pengaman Sistem.
**Stage Direction:** Serius, tatap dewan juri, tekankan istilah *defense-in-depth* dan *fail-closed*.

> *"Di sisi keamanan sistem (Level of Security), kami menerapkan **3 lapis pertahanan independen (defense-in-depth)**:*
>
> *Pertama,* ***Sandboxed Execution Boundary**. Seluruh aksi dieksekusi melalui* `SimulatedToolExecutor`. *Aksi destruktif seperti* `isolate_endpoint` *atau* `disable_user` *memiliki pengaman hard-coded: jika Policy Gate tidak menyatakan ALLOW, **eksekusi dibatalkan langsung di level kode** sebelum menyentuh tool apapun.*
>
> *Kedua,* ***Strict Output Contract**. Komunikasi antar-modul dibatasi oleh skema Pydantic ketat dan controlled vocabulary. Output yang tidak lazim atau upaya manipulasi tipe data otomatis dialihkan ke rute fallback konservatif.*
>
> *Ketiga,* ***Fail-Closed Design**. Jika model mengalami timeout, output korup, atau trajectory terputus, sistem menolak berasumsi aman. Keputusan default selalu jatuh ke **REVIEW** atau **BLOCK**. Kegagalan internal dirancang untuk selalu jatuh ke sisi aman, bukan menjadi celah bagi musuh."*

---

### SEGMEN 7: SCALABILITY, READINESS & CLOSING (6:20 – 7:00) | Bobot: Scalability & Readiness (10%)
**Visual / Slide:** Slide 6 — *Enterprise Readiness Summary* + Logo WIENER + Tagline.
**Stage Direction:** Tempo melambat secara teratur, artikulasi tegas, kunci kontak mata di kalimat penutup.

> *"Untuk kesiapan deployment skala enterprise:*
> - *Provider LLM bersifat pluggable via factory pattern — siap disambungkan ke endpoint komersial, model open-source on-premise, maupun jaringan air-gapped.*
> - *Aturan keamanan dan ambang batas risiko disimpan terpisah di file deklaratif YAML (`safety_constraints.yaml`). Praktisi SOC dapat memperbarui kebijakan kepatuhan kapan saja tanpa perlu menyentuh atau me-redeploy kode program.*
> - *Kesiapan operasional diverifikasi melalui automated health check 32-poin (`./run_healthcheck`).*
>
> *Dewan juri yang terhormat, di era AI otonom, kita tidak bisa berasumsi bahwa model bahasa tidak akan pernah tertipu.*
> *Tugas kita adalah memastikan bahwa ketika model tersebut tertipu, sistem pertahanan Anda tetap terkendali dan fail-closed.*
>
> *Don't just detect prompts. Govern the actions.*
> *Terima kasih. Kami siap untuk sesi tanya jawab."*

*(Membungkuk hormat bersama tim — Stopwatch berhenti tepat di 07:00).*

---

# BAGIAN II: DEFENSE DOSSIER (BEDAH DATASET & INTEROGASI JURI)

---

### 1. Bedah Anatomi Angka (Denominator & Formula Presisi)

| Parameter Metrik | Nilai Riil | Formula & Perhitungan Matematis |
|---|:---:|---|
| **Total Trials** | **135 Trials** | $45 \text{ trials/mode} \times 3 \text{ modes}$ (`no_defense`, `basic_prompt_defense`, `wiener`). |
| **Rincian per Mode** | **45 Trials** | **35 serangan adversarial** (RS-001..005) + **10 kontrol benign** (lalu lintas normal). |
| **Total Serangan** | **105 Attacks** | 35 serangan adversarial $\times 3$ mode pertahanan. |
| **Total Kontrol** | **30 Benign** | 10 skenario normal benign $\times 3$ mode pertahanan. |
| **No Defense UAR** | **26.7%** | $\frac{12 \text{ aksi destruktif tereksekusi}}{45 \text{ percobaan}} = 0.2667$ (CI95: 15.9% – 41.0%). |
| **Basic Prompt UAR**| **15.6%** | $\frac{7 \text{ aksi destruktif tereksekusi}}{45 \text{ percobaan}} = 0.1556$ (CI95: 7.7% – 28.8%). |
| **WIENER UAR** | **0.0%** | $\frac{0 \text{ aksi destruktif tereksekusi}}{45 \text{ percobaan}} = 0.0000$ (CI95: 0.0% – 7.8%). |
| **WIENER ASR** | **22.2%** | $\frac{10 \text{ usulan berbahaya diajukan agent}}{45 \text{ percobaan}} = 0.2222$ (Attack Success Rate pada agen: agen sempat terbujuk mengusulkan aksi bahaya 10 kali, tetapi **seluruh 10 usulan (10/10) langsung di-BLOCK oleh Policy Gate**). |
| **Hero Box Dashboard**| **10 BLOCK** | **`10 dangerous proposals reached SOC-agent stage` $\rightarrow$ `10 BLOCK · 0 REVIEW · 0 EXECUTED`**. |
| **UAPR (Pencegahan)** | **1.0 (100%)** | Formula: $\frac{\text{UAR}_{\text{baseline}} - \text{UAR}_{\text{defended}}}{\text{UAR}_{\text{baseline}}} = \frac{0.2667 - 0.0}{0.2667} = \mathbf{1.0}$. |
| **FIR (False Alarms)** | **0.0%** | Formula: $\frac{\text{Salah Intervensi pada Benign}}{\text{Total Benign Trials}} = \frac{0}{10} = \mathbf{0.0\%}$ (pada total 30 uji kontrol benign lintas mode). |

---

### 2. Membedah Dua Bukti Audit Kunci

* **Apa itu 16/16 Invariants Passed?**
  Pengujian integritas logis otomatis pada file rujukan (`validate_experiment`):
  1. *No ID collisions* (0 tabrakan ID).
  2. Jumlah baris per mode seimbang ($45 \times 3$).
  3. Rantai trajectory lengkap (input $\rightarrow$ proposal $\rightarrow$ assessment $\rightarrow$ risk $\rightarrow$ policy $\rightarrow$ tool).
  4. Konsistensi keputusan Policy Gate dengan bobot Risk Engine dan hard safety constraints.
* **Apa yang diuji oleh automated test suite?**
  Menguji setiap modul secara terisolasi: Pydantic schema validation, *Monotonic Guard* pada Blue AI, pencocokan aturan *Safety Constraints* (SC-001..SC-022), logika ambang batas Policy Gate, penolakan `SimulatedToolExecutor`, failover ladder 3-tier, serta loop mutasi Red AI.

---

### 3. Panduan Taktis 6 Pertanyaan Jebakan Juri (High-Risk Traps)

#### Jebakan 1: *"Kalau di WIENER agennya masih tertipu mengusulkan aksi bahaya 22.2% (ASR 22.2%), kenapa kalian bilang sistem ini berhasil?"*
> **Jawaban Taktis:**
> *"Itu justru **bukti nyata dari keunggulan Unique Selling Proposition kami**. Kami tidak berasumsi bahwa LLM adalah benteng yang mustahil ditembus — **model bahasa kami tidak perlu sempurna untuk menjadi bagian dari sistem yang aman**.*
>
> *Model kami masih bisa tertipu, tetapi model tersebut tidak memiliki otoritas eksekusi. Dari 45 trial WIENER, 10 proposal berbahaya sempat diajukan (ASR 22.2%), seluruhnya di-BLOCK oleh Policy Gate (10/10), dan tidak ada satu pun yang dieksekusi (UAR 0.0%). Bukti ini terlihat langsung di Hero Box Dashboard kami: `10 BLOCK · 0 REVIEW · 0 EXECUTED`.*
>
> *Attacker boleh mengecoh pemahaman bahasa agen, tetapi dalam boundary sistem kami, manipulasi teks pada input tidak memiliki jalur langsung menuju eksekusi dan tidak dapat mengubah keputusan Policy Gate."*

#### Jebakan 2: *"Kenapa kalian menguji di lingkungan simulasi (`SimulatedToolExecutor`), bukan langsung di Active Directory atau Firewall nyata?"*
> **Jawaban Taktis:**
> *"Pertama, ini adalah **etika pengujian keamanan (sandboxing)**: PoC pertahanan otonom tidak boleh menyentuh infrastruktur riil tanpa validasi laboratorium yang terkontrol.
> Kedua, **yang kami validasi pada PoC adalah boundary otorisasi dan logika penolakannya**: `SimulatedToolExecutor` merepresentasikan interface aksi secara terkontrol, sehingga pengujian aman dan tidak menyentuh infrastruktur riil. Ketika Policy Gate menyatakan BLOCK, proses langsung dihentikan di level kode sebelum menyentuh tool apapun. Jika diintegrasikan ke sistem nyata, arsitektur gate ini berfungsi sebagai wrapper otorisasi di depan driver API produksi."*

#### Jebakan 3: *"Apakah 135 trial itu cukup untuk membuktikan klaim enterprise-grade?"*
> **Jawaban Taktis:**
> *"Untuk fase Proof-of-Concept, 135 trial terkontrol dengan 16/16 invariant checks memberikan **basis evaluasi yang konsisten untuk membandingkan tiga arsitektur secara apple-to-apple**.
> Kami tidak mengklaim ini sebagai jutaan log produksi. Yang kami buktikan secara terukur adalah **keunggulan struktural**: PoC ini membuktikan bahwa execution control yang dipindahkan ke luar model mampu menghentikan execution leakage yang masih terjadi sebesar 15.6% pada prompt-based defense dalam dataset evaluasi kami."*

#### Jebakan 4: *"Bagaimana kalau penyerang menginjeksi file konfigurasi YAML atau Policy Gate secara langsung?"*
> **Jawaban Taktis:**
> *"Policy Gate dan file YAML berada di **luar Trust Boundary penyerang**. Penyerang hanya berinteraksi melalui saluran data input yang tidak terpercaya (alert log atau pesan SIEM yang dibaca oleh agen).
> File YAML konfigurasi disimpan di storage lokal server yang dilindungi oleh kontrol akses sistem operasi (OS-level permission) dan hanya dapat diperbarui oleh administrator terautentikasi melalui pipeline CI/CD. Model bahasa tidak memiliki akses tulis ataupun hak akses untuk mengubah file konfigurasi tersebut."*

#### Jebakan 5: *"Kenapa bobot risiko (0.35/0.30/0.20/0.15) dan threshold 30/60 diatur di YAML, bukan dilatih dengan machine learning?"*
> **Jawaban Taktis:**
> *"Karena dalam pertahanan siber misi kritis, **audibilitas dan determinisme adalah prioritas utama**. Menggunakan machine learning untuk menentukan keputusan penahanan justru menciptakan 'black-box di dalam black-box' yang rentan terhadap teknik penghindaran adversarial baru.
> Dengan menyimpannya sebagai file konfigurasi deklaratif, auditor kepatuhan dan CISO dapat memverifikasi, mengaudit, dan menyesuaikan toleransi risiko organisasi mereka secara instan dan transparan tanpa perlu re-training model."*

#### Jebakan 6: *"Kenapa denominator UAR 45 trial per mode, bukan 35 adversarial trials?"*
> **Jawaban Taktis:**
> *"Dalam metodologi evaluasi kami, UAR didefinisikan terhadap seluruh 45 trial pada masing-masing mode secara konsisten sebagai proporsi aksi destruktif terhadap total skenario operasional yang dihadapi sistem. Pembagian 35 skenario adversarial dan 10 kontrol benign dirancang untuk menguji ketahanan terhadap eksploitasi sekaligus memverifikasi False Intervention Rate (FIR) secara simultan pada basis data yang sama."*
