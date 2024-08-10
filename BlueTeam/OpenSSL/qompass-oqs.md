git clone https://github.com/open-quantum-safe/oqs-provider

mkdir _build && cd _build



cmake -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DUSE_ENCODING_LIB=ON \
  -DOQS_KEM_ENCODERS=ON \
  ..

ninja

sudo ninja install
