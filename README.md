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

### Web JS/TS API call example:

```JS
import createModule from './lib/sha2.web';


function SHA2() {
    (async () => {
      const wasm = await createModule();

      /* message */
      const message = new Uint8Array([
          0x61, 0x62, 0x63
      ]);
      const messageLen = message.length;
      const messagePtr = wasm._malloc(messageLen);

      /** out */
      const out = new Uint8Array(64);
      const outLen = out.length;
      const outPtr = wasm._malloc(outLen);

      /** copy to WASM memo */
      wasm.HEAPU8.set(message, messagePtr);

      /** run sha512 hash function */
      const ctx = wasm._sha512_create();
      wasm._sha512_update(ctx, messagePtr, messageLen);
      wasm._sha512_digest(ctx, outPtr);

      /** logging the result */
      const result = wasm.HEAPU8.slice(outPtr, outPtr + outLen);
      console.log(
        "SHA512:",
        Array.from(result as Uint8Array)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
      );

      /** cleanup */
      wasm._free(messagePtr);
      wasm._free(outPtr);
      wasm._sha512_destroy(ctx);
  })();

  return null;
};

export default SHA2;
```
