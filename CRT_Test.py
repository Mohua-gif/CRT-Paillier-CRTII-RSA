def extended_gcd(a, b):

    if a == 0:


        return b, 0, 1


    gcd, x1, y1 = extended_gcd(b % a, a)


    x = y1 - (b // a) * x1


    y = x1


    return gcd, x, y


def mod_inverse(a, m):


    gcd, x, y = extended_gcd(a, m)


    if gcd != 1:


        raise Exception('The modular inverse does not exist')


    else:


        return x % m



def MOD(m,e,n):
    c=(m**e)%n
    return c

def CRT(m,e,p,q):
    K_p = (m**e)%p
    K_q = (m**e)%q
    n=p*q
        # I_1 = gy.powmod(q * q, p * p - 2, p**2)
        # I_2 = gy.powmod(p * p, q * q - 2, q**2)
        
    print(mod_inverse(3,7))
    I_1=mod_inverse(q,p)
    I_2=mod_inverse(p,q)
    cipher_text = (K_p *q* I_1 + K_q * p * I_2)%n
    return cipher_text

if __name__ == '__main__':
    p=3
    q=5
    e=7
    n=15
    m=2
    c1=MOD(m,e,n)
    c2=CRT(m,e,p,q)
    print(c1)
    print(c2)