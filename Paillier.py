# From:https://blog.csdn.net/MoMummy/article/details/115006483

import gmpy2 as gy
import random
import time
import libnum
import timeit
# from line_profiler import LineProfiler

# lp = LineProfiler()


class Paillier(object):
    def __init__(self, pubKey=None, priKey=None):
        self.pubKey = pubKey
        self.priKey = priKey

    def __gen_prime__(self, rs):
        p = gy.mpz_urandomb(rs, 1024)
        while not gy.is_prime(p):
            p += 1
        return p

    def __L__(self, x, n):
        res = gy.div((x - 1), n)
        # this step is essential, directly using "/" causes bugs
        # due to the floating representation in python
        return res

    def __key_gen__(self):
        # generate random state
        while True:
            rs = gy.random_state(int(time.time()))
            p = self.__gen_prime__(rs)
            q = self.__gen_prime__(rs)
            n = p * q
            lmd = (p - 1) * (q - 1)
            # originally, lmd(lambda) is the least common multiple.
            # However, if using p,q of equivalent length, then lmd = (p-1)*(q-1)
            if gy.gcd(n, lmd) == 1:
                # This property is assured if both primes are of equal length
                break
        g = n + 1
        mu = gy.invert(lmd, n)
        # Originally,
        # g would be a random number smaller than n^2,
        # and mu = (L(g^lambda mod n^2))^(-1) mod n
        # Since q, p are of equivalent length, step can be simplified.
        self.pubKey = [n, g]
        self.priKey = [lmd, mu]
        self.para = [p, q]
        return

    def decipher(self, ciphertext):
        n, g = self.pubKey
        lmd, mu = self.priKey
        m = self.__L__(gy.powmod(ciphertext, lmd, n**2), n) * mu % n
        # print("raw message:", m)
        plaintext = libnum.n2s(int(m))
        return plaintext

    def encipher(self, plaintext):
        m = libnum.s2n(plaintext)
        n, g = self.pubKey
        r = gy.mpz_random(gy.random_state(int(time.time())), n)
        while gy.gcd(n, r) != 1:
            r += 1
        ciphertext = gy.powmod(g, m, n**2) * gy.powmod(r, n, n**2) % (n**2)
        return ciphertext

    def CRT_encipher_noFermat(self, plaintext):
        """Quick encryption of Paillier by using CRT

        Args:
            plaintext (_type_): _description_

        Returns:
            _type_: _description_
        """
        m = libnum.s2n(plaintext)
        n, g = self.pubKey
        r = gy.mpz_random(gy.random_state(int(time.time())), n)
        while gy.gcd(n, r) != 1:
            r += 1
        p, q = self.para
        R_p = gy.powmod(r, n, p**2)
        R_q = gy.powmod(r, n, q**2)
        l_p = gy.powmod(g, m, p**2)
        l_q = gy.powmod(g, m, q**2)
        I_1 = gy.invert(q * q, p * p)
        I_2 = gy.invert(p * p, q * q)
        ciphertext_1 = gy.mod(l_p * (q * q) * I_1 + l_q * (p * p) * I_2, n**2)
        ciphertext_2 = gy.mod(R_p * (q * q) * I_1 + R_q * (p * p) * I_2, n**2)
        ciphertext = gy.mod(ciphertext_1 * ciphertext_2, n**2)
        return ciphertext

    def CRT_encipher_Fermat(self, plaintext):
        m = libnum.s2n(plaintext)
        n, g = self.pubKey
        r = gy.mpz_random(gy.random_state(int(time.time())), n)
        while gy.gcd(n, r) != 1:
            r += 1
        p, q = self.para
        R_p = gy.powmod(r, n, p**2)
        R_q = gy.powmod(r, n, q**2)
        l_p = gy.powmod(g, m, p**2)
        l_q = gy.powmod(g, m, q**2)
        I_1 = gy.powmod(q * q, p * p - 2, p**2)
        I_2 = gy.powmod(p * p, q * q - 2, q**2)
        # I_1=gy.invert(q*q,p*p)
        # I_2=gy.invert(p*p,q*q)
        ciphertext_1 = gy.mod(l_p * (q * q) * I_1 + l_q * (p * p) * I_2, n**2)
        ciphertext_2 = gy.mod(R_p * (q * q) * I_1 + R_q * (p * p) * I_2, n**2)
        ciphertext = gy.mod(ciphertext_1 * ciphertext_2, n**2)
        return ciphertext


if __name__ == "__main__":

    pai = Paillier()
    pai.__key_gen__()
    pubKey = pai.pubKey
    print("Public/Private key generated.")
    # plaintext = input("Enter your text: ")
    plaintext = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    # plaintext = "Cat is the cutest."
    # Byte
    print(len(plaintext.encode("utf-8")) * 8)

    # print("Original text:", plaintext)
    ciphertext = pai.encipher(plaintext)
    # print("Ciphertext:", ciphertext)
    # deciphertext = pai.decipher(ciphertext)
    # print("Deciphertext: ", deciphertext)

    
    start_time = time.time()
    for i in range(1000):
        deciphertext = pai.decipher(ciphertext)
        i=i+1
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"代码执行时间：{execution_time} 秒")

    
    

    
   


    # timer = timeit.Timer(
    #     "pai.__key_gen__()",
    #     "from __main__ import pai",
    # )
    # execution_time = timer.timeit(number=1000)  # 执行代码1000次
    # print(f"Paillier.KEYGEN()代码执行平均时间：{execution_time / 1000*1000} 毫秒")

    timer = timeit.Timer(
        "pai.encipher('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')",
        "from __main__ import pai",
    )
    execution_time = timer.timeit(number=1000)  # 执行代码1000次
    print(f"Paillier.ENCRYPTION()代码执行平均时间：{execution_time / 1000*1000} 毫秒")

    timer = timeit.Timer(
        "pai.CRT_encipher_noFermat('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')",
        "from __main__ import pai",
    )
    execution_time = timer.timeit(number=1000)  # 执行代码1000次
    print(f"[CRT]Paillier.ENCRYPTION()代码执行平均时间：{execution_time / 1000*1000} 毫秒")



  



    
    # print("Original text:", plaintext)

    start_time = time.time()

    # ciphertext = pai.encipher(plaintext)
    ciphertext = pai.CRT_encipher_noFermat(plaintext)

    end_time = time.time()
    execution_time = end_time - start_time
    # print(f"代码执行时间：{execution_time} 秒")

    # print("Ciphertext:", ciphertext)
    # deciphertext = pai.decipher(ciphertext)
    # print("Deciphertext: ", deciphertext)

      # i = 0
    # Max_c = 0
    # Max_p = 0
    # Min_c = 10
    # Min_p = 10
    # while i < 100:
    #     print(i + 1)
    #     timer = timeit.Timer(
    #         "pai.CRT_encipher_noFermat('Cat is the cutest.')",
    #         "from __main__ import pai",
    #     )
    #     execution_time = timer.timeit(number=1000)  # 执行代码1000次
    #     print(
    #         f"CRT_encipher_noFermat 代码执行平均时间：{execution_time / 1000*1000} 毫秒"
    #     )

    #     if execution_time / 1000 * 1000 > Max_c:
    #         Max_c = execution_time / 1000 * 1000
    #     elif execution_time / 1000 * 1000 < Min_c:
    #         Min_c = execution_time / 1000 * 1000

    #     timer = timeit.Timer(
    #         "pai.encipher('Cat is the cutest.')",
    #         "from __main__ import pai",
    #     )
    #     execution_time = timer.timeit(number=1000)  # 执行代码1000次
    #     print(f"encipher代码执行平均时间：{execution_time / 1000*1000} 毫秒")
    #     i += 1

    #     if execution_time / 1000 * 1000 > Max_p:
    #         Max_p = execution_time / 1000 * 1000
    #     elif execution_time / 1000 * 1000 < Min_p:
    #         Min_p = execution_time / 1000 * 1000

    # print(f"CRT_encipher_noFermat代码执行最大时间：{Max_c} 毫秒")
    # print(f"CRT_encipher_noFermat代码执行最小时间：{Min_c} 毫秒")

    # print(f"encipher代码执行最大时间：{Max_p} 毫秒")
    # print(f"encipher代码执行最小时间：{Min_p} 毫秒")
