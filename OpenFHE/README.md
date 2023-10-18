# Build

Make sure to globally install OpenFHE in your system following OpenFHE's build instructions, i.e. `find_package(OpenFHE)` in CMake have to be successful. For the attack to work, compile the library with `NATIVE_SIZE=128`

```
mkdir build
cd build
cmake ..
make
```
Then the program could be executed in the build directory by, for example:

```./openfheattack $((2**55)) 30 16```

It will generate `attack_output.txt` file, which contains the information to recover the key.

# Test

The program `test_data.py` is designed to test intermediate values in the attack. It computes and prints them, then tries to recover the secret key. Run it with `sage -python test_data.py`, after you executed `openfheattack` program

# Graphs

One can recreate the graphs from the paper by running `sage -python graphs.py`. It uses the data from `statistics_16384.pickle` file. It is possible to collect all the data from scratch, run `sage -python graphs.py gen`