# Ethyl
C++ library for communicating with Ethereum

## Building

### Building from Source

Clone the repository as usual, including submodules (either by passing `--recurse-submodules` to
`git clone`, or else running `git submodule update --init --recursive` the top-level project
directory).

To compile the library run the following commands from the project source directory:

```
mkdir -p build
cd build
cmake ..
make -j8  # Tweak as needed for the desired build parallelism
```

Various options can be added to the `cmake ..` line; some common options are:
- `-DCMAKE_BUILD_TYPE=Release` to make a release build

## Testing

Unit tests use [Catch2](https://github.com/catchorg/Catch2) as a formal unit-test framework. Unit
tests are built by default as part of the standard CMake build logic (unless being built as a
subdirectory of another CMake project) and can be invoked through the `make test` or running the test binaries build in `build/tests`.
