n = 253963006250652707627402859040685100389
e = 65537
d = 42772482296155483517134936268603049473
partial_ct = 31639169974475525248366103533531939340


def is_valid(n):
    res = 0
    while n:
        res += n % 10
        n //= 10
    return res % 10 == 9


for i in range(10):
    ct = partial_ct + i
    pt = pow(ct, d, n)
    if is_valid(pt):
        print(pt)
