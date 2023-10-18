# Build

Make sure to globally install OpenFHE in your system following OpenFHE's build instructions, i.e. `find_package(OpenFHE)` in CMake have to be successful. For the attack to work, compile the library with `NATIVE_SIZE=128`

```
mkdir build
cd build
cmake ..
make
```
Then the program could be executed by, for example:

```./openfheattack $((2**55)) 30 16```