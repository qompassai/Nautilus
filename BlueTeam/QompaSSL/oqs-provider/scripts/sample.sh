cd /home/phaedrus/Forge/GH/Qompass/Nautilus/BlueTeam/QompaSSL/oqs-provider/scripts

sudo cmake -S liboqs -B liboqs/_build \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DUSE_OPENSSL=ON \
  -DOPENSSL_ROOT_DIR=/home/phaedrus/Forge/GH/Qompass/Nautilus/BlueTeam/QompaSSL \
  -DOPENSSL_CRYPTO_LIBRARY=/home/phaedrus/Forge/GH/Qompass/Nautilus/BlueTeam/QompaSSL/libcrypto.so.3 \
  -DOPENSSL_SSL_LIBRARY=/home/phaedrus/Forge/GH/Qompass/Nautilus/BlueTeam/QompaSSL/libssl.so.3 \
  -DOPENSSL_INCLUDE_DIR=/home/phaedrus/Forge/GH/Qompass/Nautilus/BlueTeam/QompaSSL/include

sudo cmake --build liboqs/_build --parallel 8
sudo cmake --build liboqs/_build --target install
