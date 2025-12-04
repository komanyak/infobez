# ===== File: kuznechik.py =====
import secrets
from typing import List, Tuple


class Kuznechik:
    """Реализация алгоритма шифрования 'Кузнечик' (ГОСТ 34.12-2015)"""

    BLOCK_SIZE = 16  # Длина блока в байтах

    # Таблица прямого нелинейного преобразования S
    PI = [
        0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
        0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
        0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
        0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
        0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
        0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
        0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
        0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
        0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
        0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
        0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
        0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
        0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
        0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
        0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
        0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
        0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
        0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
        0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
        0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
        0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
        0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
        0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
        0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
        0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
        0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
        0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
        0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
        0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
        0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
        0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
        0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
    ]

    # Таблица обратного нелинейного преобразования S^(-1)
    REVERSE_PI = [
        0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
        0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
        0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
        0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
        0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
        0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
        0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
        0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
        0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
        0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
        0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
        0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
        0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
        0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
        0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
        0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
        0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
        0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
        0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
        0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
        0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
        0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
        0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
        0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
        0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
        0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
        0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
        0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
        0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
        0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
        0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
        0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
    ]

    # Вектор линейного преобразования
    L_VEC = [1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148]

    def __init__(self, key: bytes = None):
        """Инициализация шифра Kuznechik с ключом 32 байта или генерация случайного"""
        if key is None:
            key = secrets.token_bytes(32)
        elif len(key) != 32:
            raise ValueError("Ключ должен быть длиной 32 байта")

        self.key1 = key[:16]
        self.key2 = key[16:]

        self.iter_key = [bytearray(16) for _ in range(10)]
        self.iter_C = [bytearray(16) for _ in range(32)]

        self._generate_C()
        self._expand_key()
        print("Инициализация Kuznechik завершена")

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        """Побитовое XOR двух байтовых строк"""
        return bytes(x ^ y for x, y in zip(a, b))

    def _S(self, data: bytes) -> bytes:
        """Функция S (нелинейное преобразование)"""
        return bytes(self.PI[b] for b in data)

    def _reverse_S(self, data: bytes) -> bytes:
        """Функция S^(-1) (обратное нелинейное преобразование)"""
        return bytes(self.REVERSE_PI[b] for b in data)

    @staticmethod
    def _gf_mul(a: int, b: int) -> int:
        """Умножение в поле Галуа GF(2^8)"""
        result = 0
        for i in range(8):
            if b & 1:
                result ^= a
            hi_bit = a & 0x80
            a <<= 1
            if hi_bit:
                a ^= 0xC3
            b >>= 1
        return result & 0xFF

    def _R(self, state: bytearray) -> bytearray:
        """Функция R (линейное преобразование)"""
        a_15 = 0
        result = bytearray(16)
        for i in range(15, 0, -1):
            result[i - 1] = state[i]
        for i in range(16):
            a_15 ^= self._gf_mul(state[i], self.L_VEC[i])
        result[15] = a_15 & 0xFF
        return result

    def _reverse_R(self, state: bytearray) -> bytearray:
        """Обратная функция R"""
        a_0 = state[15]
        result = bytearray(16)
        for i in range(1, 16):
            result[i] = state[i - 1]
            a_0 ^= self._gf_mul(result[i], self.L_VEC[i])
        result[0] = a_0 & 0xFF
        return result

    def _L(self, data: bytes) -> bytes:
        """Функция L (16 применений R)"""
        state = bytearray(data)
        for _ in range(16):
            state = self._R(state)
        return bytes(state)

    def _reverse_L(self, data: bytes) -> bytes:
        """Обратная функция L (16 применений reverse_R)"""
        state = bytearray(data)
        for _ in range(16):
            state = self._reverse_R(state)
        return bytes(state)

    def _generate_C(self):
        """Генерация констант для раундов"""
        for i in range(32):
            block = bytearray(16)
            block[0] = (i + 1) & 0xFF
            self.iter_C[i] = bytearray(self._L(block))

    def _F(self, key1: bytes, key2: bytes, const: bytes) -> Tuple[bytes, bytes]:
        """Функция Фейстеля"""
        internal = self._xor_bytes(key1, const)
        internal = self._S(internal)
        internal = self._L(internal)
        out_key1 = self._xor_bytes(internal, key2)
        out_key2 = key1
        return out_key1, out_key2

    def _expand_key(self):
        """Расширение ключа (генерация 10 раундовых ключей)"""
        key1, key2 = self.key1, self.key2
        self.iter_key[0] = bytearray(key1)
        self.iter_key[1] = bytearray(key2)
        for i in range(4):
            for j in range(8):
                key1, key2 = self._F(key1, key2, self.iter_C[8 * i + j])
            self.iter_key[2 * i + 2] = bytearray(key1)
            self.iter_key[2 * i + 3] = bytearray(key2)
        print("Расширение ключа завершено")

    def encrypt_block(self, block: bytes) -> bytes:
        """Шифрование одного блока (16 байт)"""
        if len(block) != 16:
            raise ValueError("Размер блока должен быть 16 байт")
        state = bytearray(block)
        for i in range(9):
            for j in range(16):
                state[j] ^= self.iter_key[i][j]
            for j in range(16):
                state[j] = self.PI[state[j]]
            state = bytearray(self._L(state))
        for j in range(16):
            state[j] ^= self.iter_key[9][j]
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        """Дешифрование одного блока (16 байт)"""
        if len(block) != 16:
            raise ValueError("Размер блока должен быть 16 байт")
        state = bytearray(block)
        for j in range(16):
            state[j] ^= self.iter_key[9][j]
        for i in range(8, -1, -1):
            state = bytearray(self._reverse_L(state))
            for j in range(16):
                state[j] = self.REVERSE_PI[state[j]]
            for j in range(16):
                state[j] ^= self.iter_key[i][j]
        return bytes(state)

    def encrypt(self, data: bytes, mode: str = 'ECB') -> bytes:
        """Шифрование данных с режимом (ECB, CBC, CFB, OFB)"""
        if mode not in ['ECB', 'CBC', 'CFB', 'OFB']:
            raise ValueError("Неподдерживаемый режим шифрования")
        if mode in ['ECB', 'CBC']:
            padding_len = 16 - (len(data) % 16)
            data = data + bytes([padding_len] * padding_len)
        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        encrypted_blocks = []

        if mode == 'ECB':
            for block in blocks:
                encrypted_blocks.append(self.encrypt_block(block))

        elif mode == 'CBC':
            iv = secrets.token_bytes(16)
            encrypted_blocks.append(iv)
            prev_block = iv
            for block in blocks:
                xored = self._xor_bytes(block, prev_block)
                enc_block = self.encrypt_block(xored)
                encrypted_blocks.append(enc_block)
                prev_block = enc_block

        elif mode == 'CFB':
            iv = secrets.token_bytes(16)
            encrypted_blocks.append(iv)
            prev_block = iv
            for block in blocks:
                enc = self.encrypt_block(prev_block)
                res = self._xor_bytes(block, enc[:len(block)])
                encrypted_blocks.append(res)
                prev_block = res

        elif mode == 'OFB':
            iv = secrets.token_bytes(16)
            encrypted_blocks.append(iv)
            keystream = iv
            for block in blocks:
                keystream = self.encrypt_block(keystream)
                enc_block = self._xor_bytes(block, keystream[:len(block)])
                encrypted_blocks.append(enc_block)

        print(f"Шифрование данных ({mode}) завершено")
        return b''.join(encrypted_blocks)

    def decrypt(self, encrypted_data: bytes, mode: str = 'ECB') -> bytes:
        """Дешифрование данных с режимом"""
        if mode not in ['ECB', 'CBC', 'CFB', 'OFB']:
            raise ValueError("Неподдерживаемый режим шифрования")

        if mode == 'ECB':
            blocks = [encrypted_data[i:i + 16] for i in range(0, len(encrypted_data), 16)]
            decrypted_blocks = [self.decrypt_block(b) for b in blocks]
            result = b''.join(decrypted_blocks)
            padding_len = result[-1]
            if padding_len <= 16 and all(b == padding_len for b in result[-padding_len:]):
                result = result[:-padding_len]
            return result

        elif mode == 'CBC':
            iv = encrypted_data[:16]
            blocks = [encrypted_data[i:i + 16] for i in range(16, len(encrypted_data), 16)]
            decrypted_blocks = []
            prev_block = iv
            for block in blocks:
                dec_block = self.decrypt_block(block)
                plain = self._xor_bytes(dec_block, prev_block)
                decrypted_blocks.append(plain)
                prev_block = block
            result = b''.join(decrypted_blocks)
            padding_len = result[-1]
            if padding_len <= 16 and all(b == padding_len for b in result[-padding_len:]):
                result = result[:-padding_len]
            return result

        elif mode == 'CFB':
            iv = encrypted_data[:16]
            blocks = [encrypted_data[i:i + 16] for i in range(16, len(encrypted_data), 16)]
            decrypted_blocks = []
            prev_block = iv
            for block in blocks:
                enc = self.encrypt_block(prev_block)
                plain = self._xor_bytes(block, enc[:len(block)])
                decrypted_blocks.append(plain)
                prev_block = block
            return b''.join(decrypted_blocks)

        elif mode == 'OFB':
            iv = encrypted_data[:16]
            blocks = [encrypted_data[i:i + 16] for i in range(16, len(encrypted_data), 16)]
            decrypted_blocks = []
            keystream = iv
            for block in blocks:
                keystream = self.encrypt_block(keystream)
                plain_block = self._xor_bytes(block, keystream[:len(block)])
                decrypted_blocks.append(plain_block)
            return b''.join(decrypted_blocks)

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        return bytes.fromhex(hex_str.replace(' ', '').replace('\n', ''))

    @staticmethod
    def bytes_to_hex(data: bytes) -> str:
        return data.hex().upper()


def test_kuznechik():
    print("Тестирование алгоритма 'Кузнечик'")

    # Тестовые данные
    key = bytes(range(32))
    test_block = bytes(range(16))

    kuz = Kuznechik(key)
    encrypted = kuz.encrypt_block(test_block)
    decrypted = kuz.decrypt_block(encrypted)

    print(f"Исходный блок: {test_block.hex()}")
    print(f"Зашифрованный блок: {encrypted.hex()}")
    print(f"Расшифрованный блок: {decrypted.hex()}")

    if test_block == decrypted:
        print("Тест пройден: блок расшифрован корректно")
    else:
        print("Ошибка: расшифрованный блок не совпадает")


if __name__ == "__main__":
    print("Запуск теста Kuznechik")
    test_kuznechik()
