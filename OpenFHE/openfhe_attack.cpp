#include "openfhe.h"
#include <chrono>

using namespace lbcrypto;

#define RING_DIMENSION (1 << 14)
#define USING_OPENFHE_ESTIMATOR 0

CryptoContext<DCRTPoly> GetCryptoContext(CCParams<CryptoContextCKKSRNS>& parameters);

Ciphertext<DCRTPoly> AdditionOfCiphertexts(CryptoContext<DCRTPoly>& cryptoContext, PublicKey<DCRTPoly> publicKey, std::vector<double>& plaintextVector, uint64_t t);

Ciphertext<DCRTPoly> AdditionOfCiphertextsAdversary(CryptoContext<DCRTPoly>& cryptoContext, PublicKey<DCRTPoly> publicKey, std::vector<double>& plaintextVector, uint64_t t, Ciphertext<DCRTPoly>& ct0);

/* This is quite accurate result, which OpenFHE outputs in EXEC_NOISE_ESTIMATION
 mode if you add t fresh ciphertexts 
*/
double PredictOpenFHEEstimatorOutput(uint32_t n, uint64_t t) {
    double noise = 3.19 * sqrt(double(2)/3 * n * t);
    return log2(noise);
}

double EstimateNoiseUsingOpenFHE(std::vector<double>& plaintextVector, uint64_t t);

double std_dev(std::vector<int64_t> &v) {
   int size = v.size();
   double mean = 0.0;
   double variance = 0.0;

   int64_t sum = 0;

   // Calculate the mean coefficient value
   for(int i = 0; i < size; i++) {
      sum += v[i];
   }
   mean = sum / (size);

   // Calculate the variance of the coefficient values
   for(int i = 0; i < size; i++) {
      double diff = v[i] - mean;
      variance += diff * diff;
   }
   variance /= (size);

   return sqrt(variance);
}

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        std::cout << "Usage: <program> <t> [<statisticalParameter> <plaintextSlots> <tEmpirical>]" << std::endl;
        return 1;
    }
    // number of additions of ciphertexts
    uint64_t t = std::stoull(argv[1]);
    std::cout << "t = " << t << std::endl;
    // The noise during noise flooding is increased by a factor of 2^{statisticalSecurity/2}
    uint32_t statisticalSecurity = argc>2 ? atoi(argv[2])   : 0;
    // plaintext is the vector of doubles of length plaintextSlots
    uint32_t plaintextSlots = argc>3 ? atoi(argv[3])   : 16;
    std::vector<double> plaintextVector(plaintextSlots);
    // tEmpir is the value of t used in the first step of computation
    uint64_t tEmpir = argc>4 ? atoi(argv[4])   : t;
    std::cout << "t empirical = " << tEmpir << std::endl;

    double noise;
    if (USING_OPENFHE_ESTIMATOR) {
        std::cout << "Using real noise estimator" << std::endl;
        noise = EstimateNoiseUsingOpenFHE(plaintextVector, tEmpir);
    } else {
        std::cout << "Using simulated noise estimator" << std::endl;
        noise = PredictOpenFHEEstimatorOutput(RING_DIMENSION, tEmpir);
    }
    std::cout << "Log noise \n\t" << noise << std::endl;
    std::cout << "Noise \n\t" << pow(2, noise) << std::endl;

    /* ============ PHASE 2: Attack on estimated noise ================= */
    CCParams<CryptoContextCKKSRNS> parametersEvaluation;
    parametersEvaluation.SetExecutionMode(EXEC_EVALUATION);
    parametersEvaluation.SetNoiseEstimate(noise);
    parametersEvaluation.SetDesiredPrecision(25);
    parametersEvaluation.SetStatisticalSecurity(statisticalSecurity);
    parametersEvaluation.SetNumAdversarialQueries(1);
    auto cryptoContextEvaluation = GetCryptoContext(parametersEvaluation);

    auto ringDim = cryptoContextEvaluation->GetRingDimension();
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl;
    auto q = cryptoContextEvaluation->GetModulus();
    std::cout << "CKKS scheme is using modulus " << q << std::endl;

    auto keyPairEvaluation = cryptoContextEvaluation->KeyGen();

    std::cout << "Computing the g_t(ct0, ..., ct0)" << std::endl;

    auto adv_clock_begin = std::chrono::high_resolution_clock::now();

    Ciphertext<DCRTPoly> ct0;
    auto ciphertextResult = AdditionOfCiphertextsAdversary(cryptoContextEvaluation, keyPairEvaluation.publicKey, plaintextVector, t, ct0);
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertextResult->GetCryptoParameters());
    auto dgg = cryptoParams->GetFloodingDiscreteGaussianGenerator();
    std::cout << "sigma of additional noise " << dgg.GetStd() << std::endl;


    // Decrypt final result
    Plaintext etotal;
    cryptoContextEvaluation->Decrypt(keyPairEvaluation.secretKey, ciphertextResult, &etotal);

    auto adv_clock_end = std::chrono::high_resolution_clock::now();
    std::cout << "Adversary running time with oracles = " << std::chrono::duration_cast<std::chrono::milliseconds>(adv_clock_end - adv_clock_begin).count() << " [ms]" << std::endl;

    std::cout << "Computation is done, print values to file" << std::endl;

    const std::vector<DCRTPoly>& ba = ct0->GetElements();
    std::ofstream f("attack_output.txt", std::ios::out);
    f << t << std::endl;
    f << statisticalSecurity << std::endl;
    for (size_t i = 0; i < ba.size(); ++i) {
        f << ba[i].CRTInterpolate() << std::endl;
    }
    f << etotal->GetElement<Poly>() << std::endl;
    f << keyPairEvaluation.secretKey->GetPrivateElement().CRTInterpolate() << std::endl;
    f.close();

    auto end_clock = std::chrono::high_resolution_clock::now();
    std::cout << "Printing to files time = " << std::chrono::duration_cast<std::chrono::milliseconds>(end_clock - adv_clock_end).count() << " [ms]" << std::endl;

    return 0;
}

CryptoContext<DCRTPoly> GetCryptoContext(CCParams<CryptoContextCKKSRNS>& parameters) {
    parameters.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT);

    parameters.SetSecretKeyDist(UNIFORM_TERNARY);

    // use 128 bits of security
    parameters.SetSecurityLevel(HEStd_128_classic);
    // TODO: choose correct parameters
    parameters.SetRingDim(RING_DIMENSION);

    ScalingTechnique rescaleTech = FIXEDAUTO;
    usint dcrtBits               = 105;
    usint firstMod               = 78;

    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetFirstModSize(firstMod);

    // no multiplications will be used, only additions
    parameters.SetMultiplicativeDepth(1);

    // Generate crypto context.
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    // Enable features that you wish to use.
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(LEVELEDSHE);

    return cryptoContext;
}

// compute ct_0 + ... + ct_{t-1}, where ct_i = Encrypt(Encode(plaintextVector))
// think about using ct_i = Encrypt(Encode(pv_i))
Ciphertext<DCRTPoly> AdditionOfCiphertexts(CryptoContext<DCRTPoly>& cryptoContext, PublicKey<DCRTPoly> publicKey, std::vector<double>& plaintextVector, uint64_t t) {
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(plaintextVector);
    Ciphertext<DCRTPoly> cRes = cryptoContext->Encrypt(publicKey, ptxt);
    // start from 1 since cRes is already Encrypt(0) + ct_0
    for (uint32_t i = 1; i < t; i++) {
        Ciphertext<DCRTPoly> ci = cryptoContext->Encrypt(publicKey, ptxt);
        cRes = cryptoContext->EvalAdd(cRes, ci);
    }
    return cRes;
}

#define COMPUTE_WITH_DOUBLING 1
// compute t * ct_0, where ct_0 = Encrypt(Encode(plaintextVector))
Ciphertext<DCRTPoly> AdditionOfCiphertextsAdversary(CryptoContext<DCRTPoly>& cryptoContext, PublicKey<DCRTPoly> publicKey, std::vector<double>& plaintextVector, uint64_t t, Ciphertext<DCRTPoly>& ct0) {
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(plaintextVector);
    ct0 = cryptoContext->Encrypt(publicKey, ptxt);

    #if COMPUTE_WITH_DOUBLING
    Ciphertext<DCRTPoly> cDoubles = ct0;
    Ciphertext<DCRTPoly> cRes = cDoubles;
    bool resInit = false;
    // compute it using multiplications by two
    while (t > 0) {
        if (t & 1) {
            if (!resInit) {
                cRes = cDoubles;
                resInit = true;
            } else {
                cRes = cryptoContext->EvalAdd(cRes, cDoubles);
            }
        }
        cDoubles = cryptoContext->EvalAdd(cDoubles, cDoubles);
        t >>= 1;
    }
    #else
    Ciphertext<DCRTPoly> cRes = ct0; 
    for (uint32_t i = 1; i < t; i++) {
        cRes = cryptoContext->EvalAdd(cRes, ct0);
    }
    #endif
    return cRes;
}

double EstimateNoiseUsingOpenFHE(std::vector<double>& plaintextVector, uint64_t t) {
    CCParams<CryptoContextCKKSRNS> parametersNoiseEstimation;
    parametersNoiseEstimation.SetExecutionMode(EXEC_NOISE_ESTIMATION);
    auto cryptoContextNoiseEstimation = GetCryptoContext(parametersNoiseEstimation);

    // Key Generation
    auto keyPairNoiseEstimation = cryptoContextNoiseEstimation->KeyGen();

    // We run the encrypted computation the first time.
    auto noiseCiphertext = AdditionOfCiphertexts(cryptoContextNoiseEstimation, keyPairNoiseEstimation.publicKey, plaintextVector, t);

    // Decrypt noise
    Plaintext noisePlaintext;
    cryptoContextNoiseEstimation->Decrypt(keyPairNoiseEstimation.secretKey, noiseCiphertext, &noisePlaintext);
    double noise = noisePlaintext->GetLogError();
    return noise;
}
