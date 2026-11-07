"""
Block cipher sederhana 16-bit (toy cipher, HANYA untuk pembelajaran).

Struktur : Jaringan Feistel, 4 ronde
Blok     : 16 bit  -> dibagi dua setengah (L, R) masing-masing 8 bit
Kunci    : 16 bit  -> 4 kunci ronde 8 bit
Fungsi F : F(R, k) = ROTL8(SBOX4(R XOR k), 3) XOR (R >> 1)
           SBOX4 = S-box 4 bit diterapkan pada nibble atas dan bawah.
"""

# S-box 4 bit (permutasi 0..15) -- dipilih kelompok untuk tugas ini
SBOX4 = [0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE,
         0x1, 0xF, 0x3, 0xD, 0x8, 0xA, 0x9, 0xB]

ROUNDS = 4


def rotl8(x: int, n: int) -> int:
    n %= 8
    return ((x << n) | (x >> (8 - n))) & 0xFF


def sbox8(x: int) -> int:
    """Terapkan S-box 4 bit pada kedua nibble sebuah byte."""
    return (SBOX4[(x >> 4) & 0xF] << 4) | SBOX4[x & 0xF]


def round_function(r: int, k: int) -> int:
    return rotl8(sbox8(r ^ k), 3) ^ (r >> 1)


def key_schedule(key: int) -> list:
    """Hasilkan ROUNDS kunci ronde 8 bit dari kunci 16 bit."""
    if not 0 <= key <= 0xFFFF:
        raise ValueError("Kunci harus 16 bit (0x0000 - 0xFFFF)")
    keys = []
    k = key
    for i in range(ROUNDS):
        # rotasi kiri 16 bit sebesar 5 bit tiap ronde
        k = ((k << 5) | (k >> 11)) & 0xFFFF
        hi, lo = (k >> 8) & 0xFF, k & 0xFF
        keys.append(sbox8(hi ^ lo) ^ (0x1D * (i + 1) & 0xFF))
    return keys


def encrypt_block(block: int, key: int, trace: list = None) -> int:
    """Enkripsi satu blok 16 bit. Jika trace (list) diberikan, isi dengan detail tiap ronde."""
    keys = key_schedule(key)
    left, right = (block >> 8) & 0xFF, block & 0xFF
    for i, k in enumerate(keys, start=1):
        f = round_function(right, k)
        new_left, new_right = right, left ^ f
        if trace is not None:
            trace.append((i, left, right, k, f, new_left, new_right))
        left, right = new_left, new_right
    # tukar akhir (swap) agar dekripsi simetris
    return (right << 8) | left


def decrypt_block(block: int, key: int) -> int:
    keys = key_schedule(key)
    # balikkan swap akhir
    right, left = (block >> 8) & 0xFF, block & 0xFF
    for k in reversed(keys):
        f = round_function(left, k)
        prev_right = left
        prev_left = right ^ f
        left, right = prev_left, prev_right
    return (left << 8) | right
