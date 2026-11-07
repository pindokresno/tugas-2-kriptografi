"""
Program CLI: enkripsi & dekripsi block cipher 16-bit mode ECB, CBC, CTR.

Contoh:
    python main.py demo                       # jalankan ketiga mode dengan data uji
    python main.py enc ecb --text "halo" --key 0x1A2B
    python main.py enc cbc --text "halo" --key 0x1A2B --iv 0x0F0F
    python main.py dec cbc --hex "<ciphertext hex>" --key 0x1A2B --iv 0x0F0F
    python main.py bits "1001 0110 1110 0001" --key 0x1A2B   # input biner (sesuai soal P=1001...)
"""
import argparse
import sys

import modes
from cipher import encrypt_block

DEFAULT_KEY = 0x1A2B
DEFAULT_IV = 0x0F0F
DEFAULT_CTR = 0x00C8
DEFAULT_TEXT = "Kriptografi itu menyenangkan!"


def hexs(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def bins(data: bytes) -> str:
    return " ".join(f"{b:08b}" for b in data)


def run_mode(mode: str, plain: bytes, key: int, iv: int, ctr: int) -> dict:
    if mode == "ecb":
        c = modes.ecb_encrypt(plain, key)
        d = modes.ecb_decrypt(c, key)
    elif mode == "cbc":
        c = modes.cbc_encrypt(plain, key, iv)
        d = modes.cbc_decrypt(c, key, iv)
    else:
        c = modes.ctr_crypt(plain, key, ctr)
        d = modes.ctr_crypt(c, key, ctr)
    return {"mode": mode.upper(), "cipher": c, "decrypted": d, "ok": d == plain}


def print_result(r: dict, plain: bytes) -> None:
    print(f"=== {r['mode']} ===")
    print("Plaintext (HEX) :", hexs(plain))
    print("Ciphertext (HEX):", hexs(r["cipher"]))
    print("Ciphertext (BIN):", bins(r["cipher"]))
    try:
        print("Dekripsi        :", r["decrypted"].decode("utf-8"))
    except UnicodeDecodeError:
        print("Dekripsi (BIN)  :", bins(r["decrypted"]))
    print("Round-trip      :", "BERHASIL" if r["ok"] else "GAGAL")
    print()


def parse_int(s: str) -> int:
    return int(s, 0)


def main() -> int:
    ap = argparse.ArgumentParser(description="Block cipher 16-bit: ECB, CBC, CTR")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("demo", help="jalankan semua mode dengan data uji")

    for name in ("enc", "dec"):
        p = sub.add_parser(name)
        p.add_argument("mode", choices=["ecb", "cbc", "ctr"])
        p.add_argument("--text")
        p.add_argument("--hex", help="data dalam hex (wajib untuk dec)")
        p.add_argument("--key", type=parse_int, default=DEFAULT_KEY)
        p.add_argument("--iv", type=parse_int, default=DEFAULT_IV)
        p.add_argument("--counter", type=parse_int, default=DEFAULT_CTR)

    pb = sub.add_parser("bits", help="enkripsi string biner kelipatan 16 bit di semua mode")
    pb.add_argument("bitstring")
    pb.add_argument("--key", type=parse_int, default=DEFAULT_KEY)
    pb.add_argument("--iv", type=parse_int, default=DEFAULT_IV)
    pb.add_argument("--counter", type=parse_int, default=DEFAULT_CTR)

    a = ap.parse_args()

    if a.cmd == "demo":
        plain = DEFAULT_TEXT.encode("utf-8")
        print(f"Kunci=0x{DEFAULT_KEY:04X} IV=0x{DEFAULT_IV:04X} Counter=0x{DEFAULT_CTR:04X}\n")
        for m in ("ecb", "cbc", "ctr"):
            print_result(run_mode(m, plain, DEFAULT_KEY, DEFAULT_IV, DEFAULT_CTR), plain)
        return 0

    if a.cmd == "bits":
        bits = a.bitstring.replace(" ", "")
        if set(bits) - {"0", "1"} or len(bits) % 16:
            sys.exit("String biner harus hanya 0/1 dan panjang kelipatan 16 bit")
        plain = int(bits, 2).to_bytes(len(bits) // 8, "big")
        for m in ("ecb", "cbc", "ctr"):
            print_result(run_mode(m, plain, a.key, a.iv, a.counter), plain)
        return 0

    if a.cmd == "enc":
        plain = a.text.encode("utf-8") if a.text is not None else bytes.fromhex(a.hex)
        r = run_mode(a.mode, plain, a.key, a.iv, a.counter)
        print_result(r, plain)
    else:
        data = bytes.fromhex(a.hex)
        if a.mode == "ecb":
            out = modes.ecb_decrypt(data, a.key)
        elif a.mode == "cbc":
            out = modes.cbc_decrypt(data, a.key, a.iv)
        else:
            out = modes.ctr_crypt(data, a.key, a.counter)
        print(out.decode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
