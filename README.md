# Block Cipher 16-bit: ECB, CBC, CTR

Tugas Kelompok Kriptografi. Program enkripsi dan dekripsi block cipher sederhana (toy cipher, jaringan Feistel 4 ronde) dengan ukuran blok 16 bit dan mode operasi ECB, CBC, dan Counter.

**Anggota:** Arief Fandi Satria (124140020), Pindo Kresno Wibowo Khumail Amran Irawan (124140158)

> Hanya untuk pembelajaran. Jangan dipakai untuk data nyata.

## Struktur

| Berkas | Fungsi |
|---|---|
| `cipher.py` | Cipher Feistel 16-bit, key schedule, S-box |
| `modes.py` | Padding PKCS#7, mode ECB, CBC, CTR |
| `main.py` | CLI |
| `test_cipher.py` | Unit test |

## Cara menjalankan (Python 3, tanpa dependensi)

```bash
python main.py demo
python main.py enc ecb --text "halo" --key 0x1A2B
python main.py enc cbc --text "halo" --key 0x1A2B --iv 0x0F0F
python main.py enc ctr --text "halo" --key 0x1A2B --counter 0x00C8
python main.py dec cbc --hex "<ciphertext hex>" --key 0x1A2B --iv 0x0F0F
python main.py bits "1001011011100001 1001011011100001" --key 0x1A2B
python -m unittest -v
```

## Algoritma

- `L' = R`, `R' = L XOR F(R, K_i)`, lalu swap setelah ronde terakhir
- `F(R, K) = ROTL8(SBOX(R XOR K), 3) XOR (R >> 1)`
- ECB: `C = E(P)`; CBC: `C = E(P XOR C_prev)`; CTR: `C = P XOR E(counter + i)`
