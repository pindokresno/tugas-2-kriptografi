"""Mode operasi ECB, CBC, dan CTR untuk block cipher 16-bit (2 byte)."""
from cipher import encrypt_block, decrypt_block

BLOCK_BYTES = 2


# ---------- padding PKCS#7 (ukuran blok 2 byte) ----------
def pad(data: bytes) -> bytes:
    n = BLOCK_BYTES - (len(data) % BLOCK_BYTES)
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    n = data[-1]
    if n < 1 or n > BLOCK_BYTES or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid")
    return data[:-n]


def to_blocks(data: bytes) -> list:
    return [(data[i] << 8) | data[i + 1] for i in range(0, len(data), 2)]


def from_blocks(blocks: list) -> bytes:
    out = bytearray()
    for b in blocks:
        out += bytes([(b >> 8) & 0xFF, b & 0xFF])
    return bytes(out)


# ---------- ECB ----------
def ecb_encrypt(plain: bytes, key: int) -> bytes:
    return from_blocks([encrypt_block(b, key) for b in to_blocks(pad(plain))])


def ecb_decrypt(cipher: bytes, key: int) -> bytes:
    return unpad(from_blocks([decrypt_block(b, key) for b in to_blocks(cipher)]))


# ---------- CBC ----------
def cbc_encrypt(plain: bytes, key: int, iv: int) -> bytes:
    prev, out = iv, []
    for p in to_blocks(pad(plain)):
        prev = encrypt_block(p ^ prev, key)
        out.append(prev)
    return from_blocks(out)


def cbc_decrypt(cipher: bytes, key: int, iv: int) -> bytes:
    prev, out = iv, []
    for c in to_blocks(cipher):
        out.append(decrypt_block(c, key) ^ prev)
        prev = c
    return unpad(from_blocks(out))


# ---------- CTR ----------
def ctr_crypt(data: bytes, key: int, counter: int) -> bytes:
    """Enkripsi = dekripsi. Tanpa padding; blok terakhir boleh 1 byte."""
    out = bytearray()
    for i in range(0, len(data), 2):
        stream = encrypt_block((counter + i // 2) & 0xFFFF, key)
        chunk = data[i:i + 2]
        ks = bytes([(stream >> 8) & 0xFF, stream & 0xFF])
        out += bytes(c ^ s for c, s in zip(chunk, ks))
    return bytes(out)
