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
        p = gy.mpz_urandomb(rs,1024)         #随机生成一个0~2^1024位的数
        while not gy.is_prime(p):            #判断生成的数是否是素数
            p = gy.mpz_urandomb(rs,1024)     
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
        m = libnum.s2n(plain_text)
        cipher_text = gy.powmod(m,e,n)
        return cipher_text



if __name__ == '__main__':
    rsa=Rsa()
    rsa_crt=Rsa()
    rsa.__key_gen__()
    rsa_crt.__key_gen__CRT__()
    pubKey=rsa.pubKey

    print("[RSA]Public/Private key generated.")
    plain_text = input("请输入明文：")
    #plain_text = "Cat is the cutest."

    print("明文的比特数是：",len(plain_text.encode("utf-8")) * 8)

    cipher_text=rsa.encrypt(plain_text)
    print("RSA加密后的密文是：%x"%cipher_text)


    plain_text1 = rsa_crt.decrypt_CRT(cipher_text)
    print("CRT-RSA解密后的明文是：",(plain_text1))
    plain_text2 = rsa.decrypt(cipher_text)
    print("RSA解密后的明文是：",(plain_text2))






