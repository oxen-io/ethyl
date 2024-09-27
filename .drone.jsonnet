local default_deps_base = [
  'libgmp-dev',
  'libsecp256k1-dev',
  'nlohmann-json3-dev',
  'libcurl4-openssl-dev',
];

local default_deps = ['g++'] + default_deps_base;
local docker_base = 'registry.oxen.rocks/';

local submodule_commands = [
  'git fetch --tags',
  'git submodule update --init --recursive --depth=1 --jobs=4',
];
local submodules = {
  name: 'submodules',
  image: 'drone/git',
  commands: submodule_commands,
};

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local kitware_repo(distro) = [
  'eatmydata ' + apt_get_quiet + ' install -y curl ca-certificates',
  'curl -sSL https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - >/usr/share/keyrings/kitware-archive-keyring.gpg',
  'echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ ' + distro + ' main" >/etc/apt/sources.list.d/kitware.list',
  'eatmydata ' + apt_get_quiet + ' update',
];

local debian_backports(distro, pkgs) = [
  'echo deb http://deb.debian.org/debian ' + distro + '-backports main >>/etc/apt/sources.list.d/backports.list',
  'eatmydata ' + apt_get_quiet + ' update',
  'eatmydata ' + apt_get_quiet + ' install -y ' + std.join(' ', std.map(function(p) p + '/' + distro + '-backports', pkgs)),
];

local generic_build(jobs, build_type, lto, werror, cmake_extra, build_tests, run_tests)
      = [
          'mkdir build',
          'cd build',
          'cmake .. -DCMAKE_COLOR_DIAGNOSTICS=ON -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
          '-Dethyl_WARNINGS_AS_ERRORS=' + (if werror then 'ON ' else 'OFF ') +
          '-Dethyl_ENABLE_LTO=' + (if lto then 'ON ' else 'OFF ') +
          '-Dethyl_ENABLE_UNIT_TESTING=' + (if build_tests then 'ON ' else 'OFF ') +
          cmake_extra,
          'make -j' + jobs + ' VERBOSE=1',
          'cd ..',
        ]
        + (if run_tests then [
             'cd build/test',
             './basic_tests --success --colour-mode ansi',
             './ethereum_client_tests --success --colour-mode ansi',
             'cd ..',
           ] else []);

local anvil() = {
  name: 'anvil',
  image: 'ghcr.io/foundry-rs/foundry:latest',
  pull: 'always',
  commands: ['anvil --host 0.0.0.0'],
};


// Regular build on a debian-like system:
local debian_pipeline(name,
                      image,
                      arch='amd64',
                      deps=default_deps,
                      extra_setup=[],
                      build_type='Release',
                      lto=false,
                      werror=true,
                      cmake_extra='',
                      extra_cmds=[],
                      jobs=6,
                      build_tests=true,
                      run_tests=true,
                      allow_fail=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  services: (if run_tests then [anvil()] else []),
  steps: [
    submodules,
    {
      name: 'build',
      image: image,
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, ETH_RPC: 'anvil:8545' },
      commands: [
                  'echo "Building on ${DRONE_STAGE_MACHINE}"',
                  'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                  apt_get_quiet + ' update',
                  apt_get_quiet + ' install -y eatmydata',
                ] + extra_setup
                + [
                  'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                  'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y cmake pkg-config ccache ' + std.join(' ', deps),
                ]
                + generic_build(jobs, build_type, lto, werror, cmake_extra, build_tests, run_tests)
                + extra_cmds,
    },
  ],
};

local clang(version) = debian_pipeline(
  'Debian sid/clang-' + version,
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version] + default_deps_base,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version + ' -DCMAKE_CXX_COMPILER=clang++-' + version + ' '
);

local full_llvm(version) = debian_pipeline(
  'Debian sid/llvm-' + version,
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version, ' lld-' + version, ' libc++-' + version + '-dev', 'libc++abi-' + version + '-dev']
       + default_deps_base,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version +
              ' -DCMAKE_CXX_COMPILER=clang++-' + version +
              ' -DCMAKE_CXX_FLAGS=-stdlib=libc++ ' +
              std.join(' ', [
                '-DCMAKE_' + type + '_LINKER_FLAGS=-fuse-ld=lld-' + version
                for type in ['EXE', 'MODULE', 'SHARED']
              ]) +
              ' -DOXEN_LOGGING_FORCE_SUBMODULES=ON'
);

// Macos build
local mac_builder(name,
                  build_type='Release',
                  arch='amd64',
                  werror=true,
                  lto=true,
                  cmake_extra='',
                  extra_cmds=[],
                  jobs=6,
                  build_tests=true,
                  run_tests=false,
                  allow_fail=false) = {
  kind: 'pipeline',
  type: 'exec',
  name: name,
  platform: { os: 'darwin', arch: arch },
  steps: [
    { name: 'submodules', commands: submodule_commands },
    {
      name: 'build',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: [
                  'echo "Building on ${DRONE_STAGE_MACHINE}"',
                  // If you don't do this then the C compiler doesn't have an include path containing
                  // basic system headers.  WTF apple:
                  'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
                ]
                + generic_build(jobs, build_type, lto, werror, cmake_extra, build_tests, run_tests)
                + extra_cmds,
    },
  ],
};


[
  // Various debian builds
  debian_pipeline('Debian sid', docker_base + 'debian-sid'),
  debian_pipeline('Debian sid/Debug', docker_base + 'debian-sid', build_type='Debug'),
  clang(19),
  // Not currently working because llvm-19 doesn't support char_traits<std::byte> or
  // char_traits<unsigned char>, but oxenc expects them to exist:
  //full_llvm(19),
  full_llvm(18),
  clang(16),
  full_llvm(16),
  debian_pipeline('Debian testing (i386)', docker_base + 'debian-testing/i386'),
  debian_pipeline('Debian 12 bookworm', docker_base + 'debian-bookworm'),
  debian_pipeline('Debian 11 bullseye', docker_base + 'debian-bullseye', extra_setup=debian_backports('bullseye', ['cmake'])),
  debian_pipeline('Ubuntu latest', docker_base + 'ubuntu-rolling'),
  debian_pipeline('Ubuntu 24.04 noble', docker_base + 'ubuntu-noble'),
  debian_pipeline('Ubuntu 22.04 jammy', docker_base + 'ubuntu-jammy', werror=false),
  debian_pipeline('Ubuntu 20.04 focal', docker_base + 'ubuntu-focal', deps=['g++-10'] + default_deps, extra_setup=kitware_repo('focal'), cmake_extra='-DCMAKE_C_COMPILER=gcc-10 -DCMAKE_CXX_COMPILER=g++-10'),

  // ARM builds (ARM64 and armhf)
  // run_tests=off on these for now because there isn't an arm64 foundry docker image yet (see
  // https://github.com/foundry-rs/foundry/discussions/7278)
  debian_pipeline('Debian sid (ARM64)', docker_base + 'debian-sid', arch='arm64', jobs=4, run_tests=false),
  debian_pipeline('Debian stable/Debug (ARM64)', docker_base + 'debian-stable', arch='arm64', jobs=4, build_type='Debug', run_tests=false),
  debian_pipeline('Debian stable (armhf)', docker_base + 'debian-stable/arm32v7', arch='arm64', jobs=4, run_tests=false),

  // Macos builds:
  mac_builder('macOS (Release, ARM)', arch='arm64'),
  mac_builder('macOS (Debug, ARM)', arch='arm64', build_type='Debug'),
  mac_builder('macOS (Release, Intel)'),
  mac_builder('macOS (Debug, Intel)', build_type='Debug'),
]
