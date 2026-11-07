import random
import unittest

import modes
from cipher import encrypt_block, decrypt_block


class TestCipher(unittest.TestCase):
    def test_block_roundtrip_random(self):
        rnd = random.Random(1)
        for _ in range(2000):
            k, b = rnd.randrange(65536), rnd.randrange(65536)
            self.assertEqual(decrypt_block(encrypt_block(b, k), k), b)

    def test_block_is_permutation_for_key(self):
        outs = {encrypt_block(b, 0x1A2B) for b in range(65536)}
        self.assertEqual(len(outs), 65536)

    def test_modes_roundtrip(self):
        rnd = random.Random(2)
        for n in range(0, 40):
            data = bytes(rnd.randrange(256) for _ in range(n))
            k, iv, c = 0x1A2B, 0x0F0F, 0x00C8
            self.assertEqual(modes.ecb_decrypt(modes.ecb_encrypt(data, k), k), data)
            self.assertEqual(modes.cbc_decrypt(modes.cbc_encrypt(data, k, iv), k, iv), data)
            self.assertEqual(modes.ctr_crypt(modes.ctr_crypt(data, k, c), k, c), data)

    def test_ecb_repeats_cbc_does_not(self):
        data = b"abababababab"
        e = modes.ecb_encrypt(data, 0x1A2B)
        c = modes.cbc_encrypt(data, 0x1A2B, 0x0F0F)
        eb = [e[i:i + 2] for i in range(0, 12, 2)]
        cb = [c[i:i + 2] for i in range(0, 12, 2)]
        self.assertEqual(len(set(eb)), 1)
        self.assertGreater(len(set(cb)), 1)


if __name__ == "__main__":
    unittest.main()
