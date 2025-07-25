<hr />

- [How to compile it?](#how-to-compile-it)
  - [Using Makefile](#using-makefile)
  - [Using Dockerfile](#using-dockerfile)
  - [Using Cargo](#using-cargo)
      - [Requiered dependencies](#required-dependencies)
  - [Linux x86_64 static version](#manually-for-linux-x86_64-static-version)
  - [Windows static version from Linux](#manually-for-windows-static-version-from-linux)
  - [macOS static version from Linux](#manually-for-macos-static-version-from-linux)
  - [Optimize the binary size](#optimize-the-binary-size)
  - [How to build documentation?](#how-to-build-documentation)
- [Usage](#usage)
  - [Simple usage](#simple-usage)
  - [Using disk instead of memory](#using-disk-instead-of-memory)
  - [Module FQDN resolver](#module-fqdn-resolver)

<hr />

# How to compile it?

## Using Makefile

You can use the **make** command to install RustHound or to compile it for Linux or Windows.

```bash
make install
nonehound-ce -h
```

More command in the **Makefile**:

```bash
Default:
usage: make install
usage: make uninstall
usage: make debug
usage: make release

Static:
usage: make windows
usage: make windows_x64
usage: make windows_x86
usage: make linux
usage: make linux_aarch64
usage: make linux_x86_64
usage: make linux_musl
usage: make macos
usage: make arm_musl
usage: make armv7

Without cli argument:
usage: make windows_noargs

Dependencies:
usage: make install_windows_deps
usage: make install_linux_musl_deps
usage: make install_macos_deps
```

## Using Dockerfile

Use RustHound with Docker to make sure to have all dependencies.

```bash
docker build --rm -t nonehound-ce .

# Then
docker run --rm -v $PWD:/usr/src/nonehound-ce nonehound-ce help
docker run --rm -v $PWD:/usr/src/nonehound-ce nonehound-ce windows
docker run --rm -v $PWD:/usr/src/nonehound-ce nonehound-ce linux
docker run --rm -v $PWD:/usr/src/nonehound-ce nonehound-ce macos
```

## Using Cargo

### Required dependencies

You will need to install Rust on your system.

[https://www.rust-lang.org/fr/tools/install](https://www.rust-lang.org/fr/tools/install)

RustHound supports Kerberos and GSSAPI. Therefore, it requires Clang and its development libraries, as well as the Kerberos development libraries. On Debian and Ubuntu, this means **clang-N**, **libclang-N-dev**, and **libkrb5-dev**.

For example:
```bash
# Debian/Ubuntu
sudo apt-get -y update && sudo apt-get -y install gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64
```

Here is how to compile the "release" and "debug" versions using the **cargo** command.

```bash
git clone https://github.com/g0h4n/RustHound-CE
cd RustHound-CE
cargo build --release
# or debug version
cargo b
```

The result can be found in the target/release or target/debug folder.

Below you can find the compilation methodology for each of the OS from Linux.
If you need another compilation system, please consult the list in this link: [https://doc.rust-lang.org/nightly/rustc/platform-support.html](https://doc.rust-lang.org/nightly/rustc/platform-support.html)


## Manually for Linux x86_64 static version

```bash
# Install rustup and Cargo for Linux
curl https://sh.rustup.rs -sSf | sh

# Add Linux deps
rustup install stable-x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu

# Static compilation for Linux
git clone https://github.com/g0h4n/RustHound-CE
cd RustHound-CE
CFLAGS="-lrt";LDFLAGS="-lrt";RUSTFLAGS='-C target-feature=+crt-static';cargo build --release --target x86_64-unknown-linux-gnu
```

The result can be found in the target/x86_64-unknown-linux-gnu/release folder.


## Manually for Windows static version from Linux
```bash
# Install rustup and Cargo in Linux
curl https://sh.rustup.rs -sSf | sh

# Add Windows deps
rustup install stable-x86_64-pc-windows-gnu
rustup target add x86_64-pc-windows-gnu

# Static compilation for Windows
git clone https://github.com/g0h4n/RustHound-CE
cd RustHound-CE
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-gnu
```

The result can be found in the target/x86_64-pc-windows-gnu/release folder.


## Manually for macOS static version from Linux

Amazing documentation: [https://wapl.es/rust/2019/02/17/rust-cross-compile-linux-to-macos.html](https://wapl.es/rust/2019/02/17/rust-cross-compile-linux-to-macos.html)

```bash
# Install rustup and Cargo in Linux
curl https://sh.rustup.rs -sSf | sh

# Add macOS tool chain
sudo git clone https://github.com/tpoechtrager/osxcross /usr/local/bin/osxcross
sudo wget -P /usr/local/bin/osxcross/ -nc https://s3.dockerproject.org/darwin/v2/MacOSX10.10.sdk.tar.xz && sudo mv /usr/local/bin/osxcross/MacOSX10.10.sdk.tar.xz /usr/local/bin/osxcross/tarballs/
sudo UNATTENDED=yes OSX_VERSION_MIN=10.7 /usr/local/bin/osxcross/build.sh
sudo chmod 775 /usr/local/bin/osxcross/ -R
export PATH="/usr/local/bin/osxcross/target/bin:$PATH"

# Cargo needs to be told to use the correct linker for the x86_64-apple-darwin target, so add the following to your project’s .cargo/config file:
grep 'target.x86_64-apple-darwin' ~/.cargo/config || echo "[target.x86_64-apple-darwin]" >> ~/.cargo/config
grep 'linker = "x86_64-apple-darwin14-clang"' ~/.cargo/config || echo 'linker = "x86_64-apple-darwin14-clang"' >> ~/.cargo/config
grep 'ar = "x86_64-apple-darwin14-clang"' ~/.cargo/config || echo 'ar = "x86_64-apple-darwin14-clang"' >> ~/.cargo/config

# Static compilation for macOS
git clone https://github.com/g0h4n/RustHound-CE
cd RustHound-CE
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-apple-darwin --features nogssapi
```

The result can be found in the target/x86_64-apple-darwin/release folder.


## Optimize the binary size

> 💡 To obtain an optimized compilation of RustHound add the following compilation parameters at the end of the `Cargo.toml` file.

```bash
[profile.release]
opt-level = "z"
lto = true
strip = true
codegen-units = 1
panic = "abort"
```

The size of the binary will be considerably minimized.
Basic cargo compiler commands can be used.

```bash
make windows
```

More information [here](https://github.com/johnthagen/min-sized-rust)


## How to build the documentation?

```bash
git clone https://github.com/g0h4n/nonehound-ce
cd RustHound-CE
cargo doc --open --no-deps
```

# Usage

```bash
Active Directory data collector for BloodHound Community Edition.
g0h4n <https://twitter.com/g0h4n_0>

Usage: nonehound-ce [OPTIONS] --domain <domain>

Options:
  -v...          Set the level of verbosity
  -h, --help     Print help
  -V, --version  Print version

REQUIRED VALUES:
  -d, --domain <domain>  Domain name like: DOMAIN.LOCAL

OPTIONAL VALUES:
  -u, --ldapusername <ldapusername>  LDAP username, like: user@domain.local
  -p, --ldappassword <ldappassword>  LDAP password
  -f, --ldapfqdn <ldapfqdn>          Domain Controler FQDN like: DC01.DOMAIN.LOCAL or just DC01
  -i, --ldapip <ldapip>              Domain Controller IP address like: 192.168.1.10
  -P, --ldapport <ldapport>          LDAP port [default: 389]
  -n, --name-server <name-server>    Alternative IP address name server to use for DNS queries
  -o, --output <output>              Output directory where you would like to save JSON files [default: ./]

OPTIONAL FLAGS:
  -c, --collectionmethod [<COLLECTIONMETHOD>]
          Which information to collect. Supported: All (LDAP,SMB,HTTP requests), DCOnly (no computer connections, only LDAP requests). (default: All) [possible values: All, DCOnly]
      --ldaps
          Force LDAPS using for request like: ldaps://DOMAIN.LOCAL/
  -k, --kerberos
          Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.
      --dns-tcp
          Use TCP instead of UDP for DNS queries
  -z, --zip
          Compress the JSON files into a zip archive

OPTIONAL MODULES:
      --fqdn-resolver  Use fqdn-resolver module to get computers IP address
```

## Simple usage

```bash
# Linux with username:password
nonehound-ce -d north.sevenkingdoms.local -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo -z

# Linux with username:password DCOnly collection method
nonehound-ce -c DCOnly -d north.sevenkingdoms.local -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo -z

# Linux with username:password and ldapip
nonehound-ce -d north.sevenkingdoms.local -i 192.168.56.11 -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo -z

# Linux with username:password and ldaps
nonehound-ce -d north.sevenkingdoms.local --ldaps -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo -z 
# Linux with username:password and ldaps and custom port
nonehound-ce -d north.sevenkingdoms.local --ldaps -P 3636 -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo -z 

# Tips to redirect and append both standard output and standard error to a file > /tmp/rh_output 2>&1
nonehound-ce -d north.sevenkingdoms.local --ldaps -u 'jeor.mormont@north.sevenkingdoms.local' -p '_L0ngCl@w_' -o /tmp/demo --fqdn-resolver > /tmp/rh_output 2>&1

# Windows with GSSAPI session
nonehound-ce.exe -d sevenkingdoms.local --ldapfqdn kingslanding
# Windows simple bind connection username:password (do not use single or double quotes with cmd.exe)
nonehound-ce.exe -d sevenkingdoms.local -u jeor.mormont@north.sevenkingdoms.local -p _L0ngCl@w_ -o output -z

# Kerberos authentication (Linux)
export KRB5CCNAME="/tmp/jeor.mormont.ccache"
nonehound-ce -d sevenkingdoms.local -f kingslanding -k -z
# Kerberos authentication (Windows)
nonehound-ce.exe -d sevenkingdoms.local -f kingslanding -k -z
```

## Using disk instead of memory

```bash
# Using disk instead of memory with --cache option, ldap bin datas will be stored in ".nonehound-cache/sevenkingdoms.local/ldap.bin"
nonehound-ce -c All -d sevenkingdoms.local -u vagrant -p vagrant -o /tmp/demo -z --cache

# Using --cache-buffer to set a buffer size to use when caching [default: 1000]
nonehound-ce -c All -d sevenkingdoms.local -u vagrant -p vagrant -o /tmp/demo -z --cache --cache-buffer 10000

# Using --resume to resume the collection from the last saved state file ".nonehound-cache/sevenkingdoms.local/ldap.bin"
nonehound-ce -d sevenkingdoms.local -o /tmp/demo -z --resume 
```

## Module FQDN resolver

```bash
# Linux with username:password and FQDN resolver module
nonehound-ce -d essos.local -u 'daenerys.targaryen@essos.local' -p 'BurnThemAll!' -o /tmp/demo --fqdn-resolver -z
# Linux with username:password and ldaps and FQDN resolver module and TCP DNS request and custom name server
nonehound-ce -d essos.local --ldaps -u 'daenerys.targaryen@essos.local' -p 'BurnThemAll!' -o /tmp/demo --fqdn-resolver --tcp-dns --name-server 192.168.56.12 -z

# Windows with GSSAPI session and FQDN resolver module
nonehound-ce.exe -d essos.local -f meereen -o output --fqdn-resolver -z
# Windows simple bind connection username:password and FQDN resolver module and TCP DNS request and custom name server (do not use single or double quotes with cmd.exe)
nonehound-ce.exe -d essos.local -u daenerys.targaryen@essos.local -p BurnThemAll! -o output -z --fqdn-resolver --tcp-dns --name-server 192.168.56.12 
```
