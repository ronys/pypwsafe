import unittest

import unittest
from pypwsafe import CBC, CBCEncryptor, CBCDecryptor

class DummyCipher:
    """A dummy cipher that just reverses bytes for encrypt/decrypt."""
    def encrypt(self, block: bytes) -> bytes:
        return block[::-1]

    def decrypt(self, block: bytes) -> bytes:
        return block[::-1]


class TestCBC(unittest.TestCase):

    def setUp(self):
        self.cipher = DummyCipher()
        self.iv = b"\x00" * 16

    def test_cbc_init_valid_iv(self):
        cbc = CBC(self.cipher, self.iv)
        self.assertEqual(cbc.iv, self.iv)
        self.assertEqual(cbc.block_size, 16)

    def test_cbc_init_invalid_iv_length(self):
        with self.assertRaises(ValueError):
            CBC(self.cipher, b"\x00" * 8)  # IV too short

    def test_cbc_process_invalid_data_length(self):
        cbc = CBC(self.cipher, self.iv)
        with self.assertRaises(ValueError):
            cbc._process(b"\x01" * 15, lambda b, p: (b, b))  # not multiple of 16

    def test_encrypt_decrypt_roundtrip(self):
        encryptor = CBCEncryptor(self.cipher, self.iv)
        decryptor = CBCDecryptor(self.cipher, self.iv)

        plaintext = b"A" * 16 + b"B" * 16  # 32 bytes
        ciphertext = encryptor(plaintext)
        recovered = decryptor(ciphertext)

        self.assertEqual(recovered, plaintext)

    def test_encryptor_changes_plaintext(self):
        encryptor = CBCEncryptor(self.cipher, b"\x01" * 16)
        plaintext = b"A" * 16
        ciphertext = encryptor(plaintext)

        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(len(ciphertext), len(plaintext))

    def test_decryptor_restores_plaintext(self):
        encryptor = CBCEncryptor(self.cipher, b"\x01" * 16)
        decryptor = CBCDecryptor(self.cipher, b"\x01" * 16)

        plaintext = b"Hello CBC Mode!!"  # exactly 16 bytes
        ciphertext = encryptor(plaintext)
        recovered = decryptor(ciphertext)

        self.assertEqual(recovered, plaintext)


if __name__ == "__main__":
    unittest.main()
