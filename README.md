# Repository Deprecated
## This repository is now deprecated. Ethyl now exists [here](https://github.com/session-foundation/ethyl). This is in line with announcements from [Session](https://getsession.org/blog/introducing-the-session-technology-foundation) and the [OPTF](https://optf.ngo/blog/the-optf-and-session), indicating that the OPTF has handed over the stewardship of the Session Project and token libraries to the [Session Technology Foundation](https://session.foundation), a Swiss-based foundation dedicated to advancing digital rights and innovation.

# Ethyl

C++ library for communicating with Ethereum.

## Building

Clone the repository `git clone --recursive` or if already cloned, `git
submodule update --init --recursive` at the root to ensure all source code is
retrieved.

Then run the following commands from the root of this repository:

**Linux**

```
# Install dependencies
apt install cmake build-essential libssl-dev libcurl4-openssl-dev

# Build
cmake -B build -S .
cmake --build build --parallel --verbose
```

**Windows via MSYS2 (MinGW, UCRT64, e.t.c)**

```
# Update pacman and install dependencies
pacman -Syuu # Terminal may prompt to restart before proceeding
pacman -S git base-devel libargp-devel cmake gcc libcurl-devel gmp-devel autoconf automake libtool

# Build
cmake -B build -S .
cmake --build build --parallel --verbose
```

Various options can be added to the `cmake ..` line; some common options are:
- `-DCMAKE_BUILD_TYPE=Release` to make a release build

## Testing

Unit tests use [Catch2](https://github.com/catchorg/Catch2) as a formal
unit-test framework. Unit tests are built by default as part of the standard
CMake build logic (unless being built as a subdirectory of another CMake
project) and can be invoked through the `make test` or running the test binaries
build in `build/tests`.
