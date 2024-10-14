# From:https://blog.csdn.net/weixin_43790779/article/details/105999977


import gmpy2 as gy
from gmpy2 import mpz
from numba import cuda
import binascii
import time
import timeit
import libnum


class Rsa(object):
    def __init__(self, pubKey=None, priKey=None):
        self.pubKey = pubKey
        self.priKey = priKey

    def create_prime(self,rs):
        bites=1024
        p = gy.mpz_urandomb(rs,bites)         #随机生成一个0~2^1024位的数
        while not gy.is_prime(p):            #判断生成的数是否是素数
            p = gy.mpz_urandomb(rs,bites)     
        return p
    
    def __Phi__(self,p,q):
        res=(p-1)*(q-1)
        return res
    
    def __key_gen__(self):
        while True:
            rs=gy.random_state(int(time.time()))
            p=self.create_prime(rs)
            q=self.create_prime(rs)
            phi=self.__Phi__(p,q)
            n=p*q
            e = gy.mpz_random(rs,phi)
            if gy.gcd(e,phi) == 1:
                break
        d = gy.invert(e,phi)
        self.pubKey = [e, n]
        self.priKey = [d, n]
        self.para=[p,q]
        return
    
    def __key_gen__CRT__(self):
        while True:
            rs=gy.random_state(int(time.time()))
            p=self.create_prime(rs)
            q=self.create_prime(rs)
            phi=self.__Phi__(p,q)
            n=p*q
            e = gy.mpz_random(rs,phi)
            if gy.gcd(e,phi) == 1:
                break
        d = gy.invert(e,phi)
        dp=gy.invert(e,(p-1))
        dq=gy.invert(e,(q-1))
        qInv=gy.invert(q,p)
        self.pubKey = [e, n]
        self.priKey = [dp, dq, qInv]
        self.para=[p,q]
        return

    def decrypt(self,cipher_text):
        d,n=self.priKey
        #c=libnum.s2n(cipher_text)
        m = gy.powmod(cipher_text,d,n)
        # plain_text = binascii.unhexlify(format(m, 'x')).decode('utf-8')
        plain_text = libnum.n2s(int(m))
        return plain_text

    
    def decrypt_CRT(self,cipher_text):
        dp,dq,qInv=self.priKey
        p, q = self.para
        #c=libnum.s2n(cipher_text)
        m1=gy.powmod(cipher_text,dp,p)
        m2=gy.powmod(cipher_text,dq,q)
        h=gy.mod(qInv*(m1-m2),p)
        m=m2+h*q
        plain_text = libnum.n2s(int(m))
        return plain_text

    
    def encrypt(self,plain_text):
        e,n=self.pubKey
        # m = mpz(binascii.hexlify(plain_text.encode('utf-8')), 16)
        m = libnum.s2n(plain_text)
        cipher_text = gy.powmod(m,e,n)
        return cipher_text
    
    def encrypt_CRT(self,plain_text):
        e,n=self.pubKey  
        p, q = self.para
        # m = mpz(binascii.hexlify(plain_text.encode('utf-8')), 16)
        m = libnum.s2n(plain_text)

        K_p = gy.powmod(m, e, p)
        K_q = gy.powmod(m, e, q)
        # I_1 = gy.powmod(q * q, p * p - 2, p**2)
        # I_2 = gy.powmod(p * p, q * q - 2, q**2)
        I_1=gy.invert(q,p)
        I_2=gy.invert(p,q)
        cipher_text = gy.mod(K_p *q* I_1 + K_q * p * I_2,n)







     
        # cipher_text = gy.powmod(m,e,n)
        return cipher_text



if __name__ == '__main__':
    rsa=Rsa()
    rsa_crt=Rsa()
    rsa.__key_gen__()
    rsa_crt.__key_gen__CRT__()
    # pubKey=rsa.pubKey

    print("[RSA]Public/Private key generated.")
    # plain_text = input("请输入明文：")
    plain_text = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"

    print("明文空间大小为：2^1024")
    print("明文的比特数是：",len(plain_text.encode("utf-8")) * 8)

    cipher_text=rsa.encrypt(plain_text)
    # print("RSA加密后的密文是：%x"%cipher_text)
    # crt_cipher_text=rsa.encrypt_CRT(plain_text)
    # print("CRT-RSA加密后的密文是：%x"%crt_cipher_text)
    # plain_text2 = rsa.decrypt(cipher_text)
    # print("RSA解密后的明文是：",(plain_text2))
    # plain_text3 = rsa.decrypt(crt_cipher_text)
    # print("RSA解密CRT后的明文是：",(plain_text3))
    # plain_text1 = rsa_crt.decrypt_CRT(cipher_text)
    # print("CRT-RSA解密后的明文是：",(plain_text1))
    # plain_text2 = rsa.decrypt(cipher_text)
    # print("RSA解密后的明文是：",(plain_text2))


    for_times=1000

    # start_time = time.time()
    # for i in range(for_times):
    #     rsa_crt.__key_gen__CRT__()
    # end_time = time.time()
    # print("CRTII-RSA密钥生成耗时: {:.4f}ms".format((end_time - start_time)/for_times*1000))


    # start_time = time.time()
    # for i in range(for_times):
    #     rsa.__key_gen__()
    # end_time = time.time()
    # print("RSA密钥生成耗时: {:.4f}ms".format((end_time - start_time)/for_times*1000))

    start_time = time.time()
    for i in range(for_times):
        cipher_text1=rsa.encrypt_CRT(plain_text)
    end_time = time.time()
    print("CRTII-RSA加密耗时: {:.4f}ms".format((end_time - start_time)/for_times*1000))


    start_time = time.time()
    for i in range(for_times):
         cipher_text=rsa.encrypt(plain_text)
    end_time = time.time()
    print("RSA加密耗时: {:.4f}ms".format((end_time - start_time)/for_times*1000))


    start_time = time.time()
    for i in range(for_times):
        plain_text1 = rsa_crt.decrypt_CRT(cipher_text)
    end_time = time.time()
    print("CRT-RSA解密耗时: {:.4f}ms".format((end_time - start_time)/for_times*1000))


    start_time = time.time()
    for i in range(for_times):
        plain_text2 = rsa.decrypt(cipher_text)
    end_time = time.time()
    print("RSA解密耗时: {:.4f}ms".format((end_time - start_time)/for_times*1000))


    # start_time = time.time()
    # rsa_crt_test=Rsa()
    # for i in range(10):
    #     rsa_crt_test.__key_gen__CRT__()
    #     cipher_text_full=rsa.encrypt_CRT(plain_text)
    #     plain_text_full = rsa_crt.decrypt_CRT(cipher_text_full)
    # end_time = time.time()
    # print("CRTII-RSA整体耗时: {:.4f}ms".format((end_time - start_time)/10*1000))

    # start_time = time.time()
    # rsa_test=Rsa()
    # for i in range(10):
    #     rsa_test.__key_gen__CRT__()
    #     cipher_text_full=rsa_test.encrypt(plain_text)
    #     plain_text_full = rsa_test.decrypt_CRT(cipher_text_full)
    # end_time = time.time()
    # print("CRT-RSA整体耗时: {:.4f}ms".format((end_time - start_time)/10*1000))

    # start_time = time.time()
    # rsa_test=Rsa()
    # for i in range(10):
    #     rsa_test.__key_gen__()
    #     cipher_text_full=rsa_test.encrypt(plain_text)
    #     plain_text_full = rsa_test.decrypt(cipher_text_full)
    # end_time = time.time()
    # print("RSA整体耗时: {:.4f}ms".format((end_time - start_time)/10*1000))

    # i = 0
    # Max1 = 0
    # Max2 = 0
    # Max3 = 0
    # Min1 = 10
    # Min2 = 10
    # Min3 = 10
    # while i < 100:
    #     print(i + 1)
        
    #     start_time = time.time()
    #     for k in range(1000):
    #          cipher_text=rsa_crt.encrypt_CRT(plain_text)
    #     end_time = time.time()
    #     execution_time=end_time-start_time
    #     print(f"CRTII-RSA-ENC()代码执行平均时间：{execution_time / 1000*1000} 毫秒")
       
    #     if execution_time / 1000 * 1000 > Max1:
    #         Max1 = execution_time / 1000 * 1000
    #     elif execution_time / 1000 * 1000 < Min1:
    #         Min1 = execution_time / 1000 * 1000

    #     start_time = time.time()
    #     for k in range(1000):
    #          plain_text1=rsa_crt.decrypt_CRT(cipher_text)
    #     end_time = time.time()
    #     execution_time=end_time-start_time
    #     print(f"CRTII-RSA-DEC()代码执行平均时间：{execution_time / 1000*1000} 毫秒")

    #     if execution_time / 1000 * 1000 > Max2:
    #         Max2 = execution_time / 1000 * 1000
    #     elif execution_time / 1000 * 1000 < Min2:
    #         Min2 = execution_time / 1000 * 1000

    #     start_time = time.time()
    #     for k in range(10):
    #          rsa_crt.__key_gen__CRT__()
    #     end_time = time.time()
    #     execution_time=end_time-start_time
    #     print(f"CRTII-RSA-KEYGEN()代码执行平均时间：{execution_time / 10*1000} 毫秒")

    #     if execution_time / 10 * 1000 > Max3:
    #         Max3 = execution_time / 10 * 1000
    #     elif execution_time / 10 * 1000 < Min3:
    #         Min3 = execution_time / 10 * 1000

    #     i += 1

    # print(f"CRTII-RSA-ENC()代码执行最大时间：{Max1} 毫秒")
    # print(f"CRTII-RSA-ENC()代码执行最小时间：{Min1} 毫秒")
    

    # print(f"CRTII-RSA-DEC()代码执行最大时间：{Max2} 毫秒")
    # print(f"CRTII-RSA-DEC()代码执行最小时间：{Min2} 毫秒")

    # print(f"CRTII-RSA-KEYGEN()代码执行最大时间：{Max3} 毫秒")
    # print(f"CRTII-RSA-KEYGEN()代码执行最小时间：{Min3} 毫秒")







