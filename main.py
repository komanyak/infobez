import secrets
import time
import sys
from typing import Tuple
import gmpy2
from gmpy2 import mpz, mpz_random, random_state


class RSAGeneratorGMP:
    def __init__(self):
        # Инициализация генератора случайных чисел GMP с криптографически стойким seed
        self.rand_state = random_state(secrets.randbits(128))
        # Генерация списка малых простых чисел для быстрой проверки кандидатов
        self.small_primes = self._generate_small_primes(50000)

    def _generate_small_primes(self, limit: int):
        # Решето Эратосфена для получения всех простых чисел до limit
        sieve = bytearray(b'\x01') * (limit + 1)
        sieve[0:2] = b'\x00\x00'
        for i in range(2, int(limit ** 0.5) + 1):
            if sieve[i]:
                sieve[i * i:limit + 1:i] = b'\x00' * ((limit - i * i) // i + 1)
        return [i for i in range(limit + 1) if sieve[i]]

    def _random_odd_candidate(self, bits: int) -> mpz:
        # Генерация случайного числа заданной длины с установленным старшим и младшим битом
        candidate = mpz_random(self.rand_state, mpz(1) << bits)
        candidate |= (mpz(1) << (bits - 1))  # старший бит = 1
        candidate |= mpz(1)  # нечётное
        return candidate

    def generate_large_prime(self, bits: int, mr_rounds: int = 64) -> mpz:
        # Генерация большого простого числа с использованием Miller-Rabin
        attempts = 0
        while True:
            attempts += 1
            candidate = self._random_odd_candidate(bits)
            candidate_int = int(candidate)
            # Быстрая проверка на делимость первыми 1000 малыми простыми числами
            if any(candidate_int % p == 0 for p in self.small_primes[:1000]):
                continue
            # Вероятностный тест простоты
            if gmpy2.is_prime(candidate, mr_rounds):
                print(f"Простое число {bits}-бит найдено за {attempts} попыток")
                return candidate

    def generate_rsa_keys(self, modulus_bits: int = 4096) -> Tuple[Tuple[mpz, mpz], Tuple[mpz, mpz, mpz, mpz]]:
        if modulus_bits % 2 != 0:
            raise ValueError("Число бит должно быть чётным")
        prime_bits = modulus_bits // 2

        print(f"Генерация p ({prime_bits} бит)...")
        p = self.generate_large_prime(prime_bits)
        print("p сгенерирован")

        print(f"Генерация q ({prime_bits} бит)...")
        while True:
            q = self.generate_large_prime(prime_bits)
            if q != p:
                break
        print("q сгенерирован")

        # Вычисляем модуль и функцию Эйлера
        n = p * q
        phi = (p - 1) * (q - 1)

        # Выбор публичной экспоненты
        e = mpz(65537)
        while gmpy2.gcd(e, phi) != 1:
            e += 2

        # Вычисление секретной экспоненты
        d = gmpy2.invert(e, phi)

        print(f"RSA-{modulus_bits} ключи сгенерированы: n={n.bit_length()} бит")
        public_key = (n, e)
        private_key = (n, d, p, q)
        return public_key, private_key

    def save_keys(self, public_key: Tuple[mpz, mpz], private_key: Tuple[mpz, mpz, mpz, mpz]):
        n, e = public_key
        _, d, p, q = private_key
        # Сохранение ключей в hex формате
        with open("public.key", "w", encoding='utf-8') as f:
            f.write(f"n={hex(int(n))[2:]}\n")
            f.write(f"e={hex(int(e))[2:]}\n")
        with open("private.key", "w", encoding='utf-8') as f:
            f.write(f"n={hex(int(n))[2:]}\n")
            f.write(f"d={hex(int(d))[2:]}\n")
            f.write(f"p={hex(int(p))[2:]}\n")
            f.write(f"q={hex(int(q))[2:]}\n")
        print("Ключи сохранены в файлы public.key и private.key")


def main():
    modulus_bits = 4096
    if len(sys.argv) > 1:
        modulus_bits = int(sys.argv[1])

    print(f"Начало генерации RSA-{modulus_bits} ключей")
    generator = RSAGeneratorGMP()
    start_total = time.time()
    public_key, private_key = generator.generate_rsa_keys(modulus_bits)
    generator.save_keys(public_key, private_key)
    total_time = time.time() - start_total
    print(f"Генерация завершена за {total_time:.2f} секунд")


if __name__ == "__main__":
    main()
