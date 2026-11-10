# Tutorial Install Symbol Linux (ISF)

Panduan ini dipakai kalau plugin Linux gagal karena symbol table (ISF) untuk kernel di memory dump belum ada atau tidak cocok.

## Tanda masalahnya

GUI menampilkan pesan seperti ini:

```text
✖ linux.pslist.PsList gagal (exit code 1).
Kemungkinan besar symbol table (ISF) untuk kernel ini belum ada.
```

Di file `.error.log` biasanya ada dua baris berikut:

```text
Unsatisfied requirement plugins.PsList.kernel.layer_name:
Unsatisfied requirement plugins.PsList.kernel.symbol_table_name:
```

Kalau ISF belum ada, error `translation layer` juga bisa ikut muncul. Itu belum tentu berarti dump-nya rusak, jadi cek ISF dulu.

## Langkah 1: Cari banner kernel

Jalankan plugin `banners.Banners` dari GUI, lalu cari baris yang paling lengkap. Contoh:

```text
Linux version 6.8.0-138-generic (buildd@lcy02-amd64-008) (...) #138~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug  7 13:43:15 UTC  (Ubuntu 6.8.0-138.138~22.04.1-generic 6.8.12)
```

Catat bagian-bagian ini:

| Bagian | Contoh | Fungsi |
|---|---|---|
| Distro | `Ubuntu` | Folder pertama di repo symbol |
| Versi kernel | `6.8.0` | Folder versi |
| ABI | `138` | Folder nomor build |
| Flavor | `generic` | Folder jenis kernel |
| Build | `#138~22.04.1-Ubuntu` | Penentu file yang harus dipilih |

## Langkah 2: Cari ISF yang cocok

Buka repo [Abyss-W4tcher/volatility3-symbols](https://github.com/Abyss-W4tcher/volatility3-symbols), lalu masuk ke folder dengan pola berikut:

```text
<Distro>/amd64/<versi>/<abi>/<flavor>
```

Contoh: [`Ubuntu/amd64/6.8.0/138/generic`](https://github.com/Abyss-W4tcher/volatility3-symbols/tree/master/Ubuntu/amd64/6.8.0/138/generic)

Kalau folder itu berisi lebih dari satu file, pilih yang sesuai dengan bagian `#...` di banner:

| Banner | File yang dipilih |
|---|---|
| `#138~22.04.1-Ubuntu` | `Ubuntu_6.8.0-138-generic_6.8.0-138.138~22.04.1_amd64.json.xz` |
| `#138-Ubuntu` | `Ubuntu_6.8.0-138-generic_6.8.0-138.138_amd64.json.xz` |

Versi kernel yang sama belum tentu cocok. ISF harus sesuai dengan build kernel di dump.

## Langkah 3: Download file ISF

1. Klik nama file `.json.xz` di GitHub.
2. Klik **Download raw file**.
3. Pastikan ukuran file yang ter-download sama dengan ukuran di GitHub.

Jangan pakai "Save link as" dari halaman daftar file, karena yang tersimpan nanti halaman HTML.

## Langkah 4: Pasang ISF

Taruh file di folder ini. Kalau folder `linux` belum ada, buat dulu:

```text
C:\Users\ATHAR\Documents\Forensil-Tools\volatility3\volatility3\symbols\linux
```

Lewat PowerShell:

```powershell
cd C:\Users\ATHAR\Documents\Forensil-Tools\volatility3
New-Item -ItemType Directory -Force volatility3\symbols\linux
Move-Item "$env:USERPROFILE\Downloads\Ubuntu_6.8.0-138-generic_6.8.0-138.138~22.04.1_amd64.json.xz" volatility3\symbols\linux\
```

Hal yang perlu diingat:

- Jangan ekstrak file `.json.xz`.
- Tidak perlu mengganti nama file, karena Volatility mengenali ISF dari banner di dalam file.
- Satu file ini dipakai bersama oleh `vol-rs` dan `vol.py`, jadi tidak perlu dipasang dua kali.

## Langkah 5: Jalankan ulang

Jalankan lagi plugin Linux dari GUI, misalnya `linux.pslist`. Run pertama bisa lebih lama karena dump perlu di-scan dan ISF perlu dibaca.

## Kalau ISF tidak ada di repo Abyss

Buat ISF sendiri dengan [dwarf2json](https://github.com/volatilityfoundation/dwarf2json). Contoh ini untuk kernel Ubuntu dan dijalankan di WSL. Siapkan koneksi internet, ruang disk yang cukup, dan RAM yang lega. Paket debug untuk kernel contoh saja berukuran sekitar 1,1 GB.

> Alur ini belum diuji pada dump contoh, karena ISF-nya sudah tersedia di repo Abyss. Nama paket dan foldernya bisa berbeda untuk kernel lain.

**1. Build dwarf2json**

```bash
git clone https://github.com/volatilityfoundation/dwarf2json
cd dwarf2json
go build
```

**2. Cari paket debug kernel**

Paket debug Ubuntu ada di [ddebs.ubuntu.com](http://ddebs.ubuntu.com/pool/main/l/). Kernel HWE seperti contoh di atas ada di folder `linux-hwe-6.8`.

```bash
wget "http://ddebs.ubuntu.com/pool/main/l/linux-hwe-6.8/linux-image-unsigned-6.8.0-138-generic-dbgsym_6.8.0-138.138~22.04.1_amd64.ddeb"
```

Versi paket harus sama dengan versi di banner.

**3. Ekstrak `vmlinux`**

```bash
mkdir ddeb
dpkg-deb -x linux-image-unsigned-6.8.0-138-generic-dbgsym_6.8.0-138.138~22.04.1_amd64.ddeb ddeb
ls ddeb/usr/lib/debug/boot/
```

**4. Buat ISF**

```bash
./dwarf2json linux --elf ddeb/usr/lib/debug/boot/vmlinux-6.8.0-138-generic | xz -9 > Ubuntu_6.8.0-138-generic.json.xz
```

**5. Pasang hasilnya**

Taruh file `.json.xz` di `volatility3/symbols/linux`, lalu jalankan ulang plugin dari GUI.

## Kalau masih gagal

| Kondisi | Yang perlu dicek |
|---|---|
| Error tetap sama | Bandingkan lagi bagian `#...` di banner dengan nama file ISF |
| Ukuran file tidak sama dengan GitHub | Download ulang, kemungkinan yang tersimpan bukan file aslinya |
| File diekstrak jadi `.json` | Hapus, lalu pakai file `.json.xz` yang asli |
| File salah tempat | Pastikan ada di `volatility3\symbols\linux`, bukan di `symbols\` langsung |
| ISF sudah benar tapi tetap tidak terbaca | Jalankan sekali lewat terminal dengan `--clear-cache` |
| `banners.Banners` tidak menemukan banner Linux | Cek dump, kemungkinan rusak, terpotong, atau bukan dump Linux |

Contoh `--clear-cache` di PowerShell:

```powershell
cd C:\Users\ATHAR\Documents\Forensil-Tools\volatility3
.\bin\vol-rs.exe -s volatility3\symbols --clear-cache -f "C:\path\ke\memory.lime" linux.pslist
```

## Contoh kasus: memory.lime HackToday Final

| Item | Nilai |
|---|---|
| Kernel | `6.8.0-138-generic` |
| Build | `#138~22.04.1-Ubuntu` |
| ISF | `Ubuntu_6.8.0-138-generic_6.8.0-138.138~22.04.1_amd64.json.xz` |
| Ukuran ISF | 2.883.468 byte |
| Hasil `linux.pslist` | 285 baris, sama antara `vol-rs` dan `vol.py` |

Hasil di atas diuji di WSL memakai `bin/vol-rs` versi Linux dan `vol.py`.
