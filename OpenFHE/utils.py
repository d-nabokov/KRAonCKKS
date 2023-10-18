import re
from sage.all import *

def vec_from_str(s, size=None):
    l = list(int(x) for x in s.split(' '))
    if size:
        return l + [0] * (size - len(l))
    else:
        return l
    
    
def read_openfhe_vector(line, size=None):
    pat = re.compile(r'COEF: \[((\d+ ?)+)\] modulus: (\d+)')
    m = pat.match(line)
    if m:
        q = int(m[3])
        v = vec_from_str(m[1], size)
        return v, q
    else:
        print('WARNING: no match for vector')
        return None, None
    
    
def to_centered_representaion(v, q):
    res = list(int(x) for x in v)
    for i in range(len(v)):
        if res[i] > q//2:
            res[i] -= q
    return res
    

# this is the actual sigma of the noise used in encryption
def compute_real_sigma_1(n):
    return 3.19 * sqrt(4/3 * n)
    
    
# this is the estimation by EXEC_NOISE_ESTIMATION mode of the noise used in fresh encryption
# is there a bug in OpenFHE implementation?
def compute_estimated_sigma_1(n):
    return 3.19 * sqrt(2/3 * n)
    

# estimated by EXEC_NOISE_ESTIMATION mode noise after computing t additions of fresh ciphertexts
def compute_estimated_sigma_2(n, t, statistical_param):
    return compute_estimated_sigma_1(n) * sqrt(12 * t) * 2**(statistical_param/2)


def compute_noise_factor(n, t, statistical_param):
    sigma_a = t * compute_real_sigma_1(n)
    sigma_b = compute_estimated_sigma_2(n, t, statistical_param)
    sigma = sqrt(sigma_a**2 + sigma_b**2)
    f = sigma_a**2 / sigma**2
    # f is the mu of t * e, we want mu of e, therefore, divide by t
    return float(f / t)


def compute_resulted_sigma(n, t, statistical_param):
    sigma_a = t * compute_real_sigma_1(n)
    sigma_b = compute_estimated_sigma_2(n, t, statistical_param)
    sigma = sqrt(sigma_a**2 + sigma_b**2)
    f = sigma_a * sigma_b / sigma
    # f is the std dev of t * e, we want std dev of e, therefore, divide by t
    return float(f / t)
    
    
def read_parameters_from_file():
    filename = './build/attack_output.txt'
    with open(filename, 'rt') as f:
        t = int(f.readline())
        statistical_parameter = int(f.readline())

        b, q = read_openfhe_vector(f.readline())
        n = len(b)

        a, qprime = read_openfhe_vector(f.readline(), size=n)
        assert(q == qprime)

        etotal, qprime = read_openfhe_vector(f.readline(), size=n)
        assert(q == qprime)
        etotal = to_centered_representaion(etotal, q)

        s, qprime = read_openfhe_vector(f.readline(), size=n)
        assert(q == qprime)
        s = to_centered_representaion(s, q)
    return t, statistical_parameter, n, q, b, a, etotal, s