Forte
======

Forte is a verifying OpenPGP key server, based on Hagrid.

You can find general instructions and an API documentation at the running
instance at [https://keys.openpgp.org](https://keys.openpgp.org).

License
-------

Forte is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hagrid is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
License for more details.

You should have received a copy of the GNU Affero General Public
License along with Hagrid.  If not, see
<https://www.gnu.org/licenses/>.

Quick Start
-----------

Building Forte requires a working stable Rust toolchain.
The easiest way to get the toolchain is to download [rustup](https://rustup.rs).

Additionally, some external dependencies are required.
Get them (on Debian or Ubuntu) with

```bash
sudo apt install gnutls-bin nettle-dev gcc llvm-dev libclang-dev build-essential pkg-config gettext
```
Get them on Arch Linux with
```bash
sudo pacman -S gnutls nettle gcc llvm clang base-devel pkgconf gettext
```
After Rust and the other dependencies are installed, copy the config file, then simply compile and run:

```bash
cd hagrid
cp Rocket.toml.dist Rocket.toml
cargo run
```

This will spawn a web server listening on port 8080.

For deployment, a release build should be used (`cargo build --release`). This
will be statically built, and can be copied anywhere. You will also need to
adjust `Rocket.toml` accordingly.  Hagrid uses `sendmail` for mailing, so you
also need a working local mailer setup.

Reverse Proxy
-------------

Hagrid is designed to defer lookups to reverse proxy server like Nginx.
Lookups via `/vks/v1/by-finingerprint`, `/vks/v1/by-keyid`, and
`/vks/v1/by-email` can be handled by a robust and performant HTTP server.
A sample configuration for nginx is part of the repository (`nginx.conf`,
`hagrid-routes.conf`).
Note that we make use of
[ngx_http_lua_module](https://github.com/openresty/lua-nginx-module) to
perform some request rewrites.


