### collect statistics about the attack

import shlex
import subprocess
import os
import sys
import numpy as np
import pickle
from sage.all import *
from utils import *

def run_program(t, statistical_param):
    t = int(t)
    program_path = './build/openfheattack'
    real_path = os.path.realpath(program_path)
    program_dir = os.path.dirname(real_path)
    program = os.path.basename(real_path)

    args = shlex.split(f'./{program} {t} {statistical_param}')
    p = subprocess.Popen(args, cwd=program_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p.wait()


def try_attack_and_get_info_about_eprime(t, statistical_parameter, n, q, b, a, etotal, s):
    stat = statistical_parameter
    scaled_etotal = list(int(round(etotal_i * compute_noise_factor(n, t, stat))) for etotal_i in etotal)
    bprime = R(b) - R(scaled_etotal)
    eprime = bprime + R(a) * R(s)
    eprime = to_centered_representaion(list(eprime), q)
    eprime_weight = sum((0 if x == 0 else 1) for x in eprime)
    eprime_stddev = np.std(eprime)

    success = (eprime_weight == 0)
    return success, eprime_weight, eprime_stddev

def collect_statistics(n):
    # Collect the data for the graphs
    runs = 100
    logt_values = np.arange(16, 27 + 0.1, 0.5)

    statistics = {}
    for statistical_param in (0, 30):
        print(f'statistical parameter = {statistical_param}')
        statistics_for_stat = {}
        for logt in logt_values:
            # OpenFHE is using dynamic q based on estimated noise for NATIVE_SIZE=128
            q_n_initialized = False
            shifted_logt = logt + statistical_param
            print(f'Working on logt={shifted_logt}, log(orig_t)={logt}')
            statistics_for_stat[logt] = list()
            for run in range(runs):
                print(f'run number {run}', end='\r')
                run_program(2**shifted_logt, statistical_param)
                t, statistical_parameter, n, q, b, a, etotal, s = read_parameters_from_file()
                if not q_n_initialized:
                    q_n_initialized = True
                    Rx = PolynomialRing(IntegerModRing(q), 'x')
                    xbar = Rx.gen()
                    R = Rx.quotient(xbar**n + 1, 'x')
                success, eprime_weight, eprime_stddev = try_attack_and_get_info_about_eprime(t, statistical_parameter, n, q, b, a, etotal, s)
                statistics_for_stat[logt].append((success, eprime_weight, eprime_stddev))
        statistics[statistical_param] = statistics_for_stat
    with open(f'statistics_{n}.pickle', 'wb') as handle:
        pickle.dump(statistics, handle, protocol=pickle.HIGHEST_PROTOCOL)

# Create the graphs
import matplotlib.pyplot as plt
plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42

n = 2**14

### Run the program with 'gen' argument to collect statistics again (takes at least several hours)
if len(sys.argv) >= 1 and sys.argv[1] == 'gen':
    collect_statistics(n)
with open(f'statistics_{n}.pickle', 'rb') as handle:
    statistics = pickle.load(handle)

stat_values = [0, 30]
logt_values = sorted(statistics[stat_values[0]].keys())
runs = len(statistics[stat_values[0]][logt_values[0]])

fig1, ax1 = plt.subplots(1, 1, figsize=(7, 5))
fig2, ax2 = plt.subplots(1, 1, figsize=(7, 5))
fig3, ax3 = plt.subplots(1, 1, figsize=(7, 5))


for stat in stat_values:
    if stat != 0:
        continue
    avg_noise_weight = list(sum(triple[1] for triple in statistics[stat][logt])/runs for logt in logt_values)
    ax1.plot(logt_values, avg_noise_weight, label=f"s = {stat}", color='red', linestyle='-')


ax1.set_xlabel(r'$\log(t) - \nu$')


ax2.plot(logt_values, list(sum(triple[2] for triple in statistics[0][logt])/runs for logt in logt_values), label=r'empirical, $\nu=0$', color='red', linestyle='-')
ax2.plot(logt_values, list(sum(triple[2] for triple in statistics[30][logt])/runs for logt in logt_values), label=r'empirical, $\nu=30$', color='blue', linestyle='--')
ax2.plot(logt_values, list(compute_resulted_sigma(n, 2**(logt+stat), stat) for logt in logt_values), label='theoretical', color='green', linestyle=':')
ax2.set_xlabel(r'$\log(t) - \nu$')
ax2.set_ylabel(r'$\sigma_{\sf attack}$')
ax2.legend()

logt_values_for_prob = list(logt for logt in logt_values if logt >= 25)
ax3.plot(logt_values_for_prob, list( sum((1 if triple[1] <= 2 else 0) for triple in statistics[30][logt])/len(statistics[30][logt]) for logt in logt_values_for_prob), color='red', marker='x', linestyle='')
ax3.plot(logt_values_for_prob, list( sum((1 if triple[1] <= 0 else 0) for triple in statistics[30][logt])/len(statistics[30][logt]) for logt in logt_values_for_prob), color='blue', marker='.', linestyle='')
ax3.grid()
ax3.set_xticks(logt_values_for_prob)
ax3.set_xlabel(r'$\log(t) - \nu$')
ax3.set_ylabel(r'success probability')


if not os.path.exists('figures'):
   os.makedirs('figures')
fig1.tight_layout()
fig1.savefig('figures/weight_eprime.pdf')
fig2.tight_layout()
fig2.savefig('figures/stddev_comparison_s30.pdf')
fig3.tight_layout()
fig3.savefig('figures/success_prob.pdf')