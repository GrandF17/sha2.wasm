# SHA2 for WASM

## Testing

### Build for testing using cmake:

```bash
cmake -S . -B build
cmake --build build
```

### Run tests:

```bash
./build/src/tests/sha2
```

## Building WASM

### Install Emscripten:

```bash
sudo apt install emscripten
```

or:

```bash
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest
source ./emsdk_env.sh
emcc -v # version check
```

### Build for Web:

```bash
mkdir wasm ; emcc ./src/lib/sha2.wasm.cpp \
  -O3 \
  -std=c++17 \
  -s MODULARIZE=1 \
  -s EXPORT_ES6=1 \
  -s ENVIRONMENT=web \
  -s SINGLE_FILE=0 \
  -s WASM=1 \
  -s EXPORT_NAME=createSHA2Module \
  -s EXPORTED_FUNCTIONS='[
    "_sha224_create",
    "_sha224_update",
    "_sha224_digest",
    "_sha224_destroy",
    "_sha256_create",
    "_sha256_update",
    "_sha256_digest",
    "_sha256_destroy",
    "_sha384_create",
    "_sha384_update",
    "_sha384_digest",
    "_sha384_destroy",
    "_sha512_create",
    "_sha512_update",
    "_sha512_digest",
    "_sha512_destroy",
    "_malloc",
    "_free"
  ]' \
  -s EXPORTED_RUNTIME_METHODS='["HEAPU8"]' \
  -o wasm/sha2.web.js
```
