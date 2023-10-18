import numpy as np
from sage.all import *
from utils import *


def partly_print_vec(v, values_to_print):
    print(f'{v[:values_to_print]}\b, ...], std dev = {np.std(v):.3f}')
    

# find x such that x = r_i mod a_i, x is not modulo prod a_i
def my_crt(r_list, a_list):
    M = 1
    for ai in a_list:
        M *= ai
    res = 0
    for ri, ai in zip(r_list, a_list):
        Mi = M // ai
        Mi_inv = inverse_mod(Mi, ai)
        res += ri * Mi * Mi_inv
    return res


def inverse_poly_mod_nonprime(a, n, q):
    assert(type(a) is list)
    qfactors = factor(q)
    qfactors = list(prime**power for prime, power in qfactors)
    ainv_polys = []
    for p in qfactors:
        Rix = PolynomialRing(IntegerModRing(p), 'x')
        gcd, ainv, _ = xgcd(Rix(a), Rix.gen()**n+1)
        assert(gcd == 1)
        ainv_polys.append(ainv.change_ring(Rx))
    ainv = my_crt(ainv_polys, qfactors)
    # hack
    return R(list(ainv))


t, statistical_parameter, n, q, b, a, etotal, s = read_parameters_from_file()

stat = statistical_parameter
n = len(b)
Rx = PolynomialRing(IntegerModRing(q), 'x')
xbar = Rx.gen()
R = Rx.quotient(xbar**n + 1, 'x')

sigma1 = compute_real_sigma_1(n)
sigma2 = compute_estimated_sigma_2(n, t, stat)
print(f'sigma_1 = {float(sigma1):.3f}')
print(f'sigma_2 = {float(sigma2):.3f}')

e = R(b) + R(a) * R(s)
enew = R(etotal) - t*e

values_to_print = 15
print('b + as = e = ')
partly_print_vec(to_centered_representaion(list(e), q), values_to_print)
print('enew = ')
partly_print_vec(to_centered_representaion(list(enew), q), values_to_print)
print('etotal = ')
partly_print_vec(etotal, values_to_print)


scaled_etotal = list(int(round(etotal_i * compute_noise_factor(n, t, stat))) for etotal_i in etotal)
print('scaled_etotal = ')
partly_print_vec(to_centered_representaion(list(scaled_etotal), q), values_to_print)
bprime = R(b) - R(scaled_etotal)

eprime = bprime + R(a) * R(s)
print('eprime = ')
partly_print_vec(to_centered_representaion(list(eprime), q), values_to_print)

print(f'eprime_sigma = {compute_resulted_sigma(n, t, stat):.3f}')
print('Trying to retrieve the secret:')
ainv = inverse_poly_mod_nonprime(a, n, q)
sprime = bprime * ainv * (-1)
print(f'Got a correct secret: {R(s) == sprime}')