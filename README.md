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
    "_sha224",
    "_sha256",
    "_sha384",
    "_sha512",
    "_hmac_sha224",
    "_hmac_sha256",
    "_hmac_sha384",
    "_hmac_sha512",
    "_malloc",
    "_free"
  ]' \
  -s EXPORTED_RUNTIME_METHODS='["HEAPU8"]' \
  -o wasm/sha2.web.js
```

### Web API call example:

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

    /* key */
    const key = new Uint8Array([
        0x61, 0x62, 0x63
    ]);
    const keyLen = key.length;
    const keyPtr = wasm._malloc(keyLen);

    /** out */
    const out = new Uint8Array(64);
    const outLen = out.length;
    const outPtr = wasm._malloc(outLen);

    /** copy to WASM memo */
    wasm.HEAPU8.set(message, messagePtr);
    wasm.HEAPU8.set(key, keyPtr);

    /** run sha512 hash function */
    wasm._hmac_sha512(messagePtr, messageLen, keyPtr, keyLen, outPtr);

    /** logging the result */
    const result = wasm.HEAPU8.slice(outPtr, outPtr + outLen);
    console.log(
      "HMAC-SHA512:",
      Array.from(result as Uint8Array)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
    );

    /** cleanup */
    wasm._free(keyPtr);
    wasm._free(messagePtr);
    wasm._free(outPtr);
  })();

  return null;
};

export default SHA2;
```
