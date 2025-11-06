# OpenTDF WASM

WebAssembly bindings for OpenTDF (Trusted Data Format), enabling data-centric security in both browser and Node.js environments.

## Features

- Create TDF archives with encrypted data
- Read TDF archives and access manifests
- Attribute-Based Access Control (ABAC) policy evaluation
- Works in both browser and Node.js environments
- Zero-copy operations where possible

## Installation

### From GitHub Packages (Recommended)

The package is published to GitHub Packages. You'll need a GitHub account and a personal access token.

**Step 1:** Create a GitHub [Personal Access Token](https://github.com/settings/tokens) with `read:packages` permission.

**Step 2:** Configure npm to use GitHub Packages. Create/update `~/.npmrc`:

```
@arkavo-org:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN
```

**Step 3:** Install the package:

```bash
npm install @arkavo-org/opentdf-wasm
```

See [NPM_PUBLISHING.md](NPM_PUBLISHING.md) for detailed installation instructions, CI/CD setup, and troubleshooting.

### From GitHub Releases

Download pre-built WASM binaries without npm:

```bash
# Download and extract
wget https://github.com/arkavo-org/opentdf-rs/releases/latest/download/opentdf-wasm-combined.tar.gz
tar -xzf opentdf-wasm-combined.tar.gz

# Contains web/ and node/ directories ready to use
```

## Usage

### Browser

```javascript
import init, { tdf_create, tdf_read, access_evaluate, version } from '@arkavo-org/opentdf-wasm';

// Initialize the WASM module
await init();

console.log('OpenTDF WASM version:', version());

// Create a TDF
const data = btoa('Sensitive information'); // Base64 encode
const policy = {
  uuid: crypto.randomUUID(),
  body: {
    attributes: [],
    dissem: ['user@example.com']
  }
};

const result = tdf_create(
  data,
  'https://kas.example.com',
  JSON.stringify(policy)
);

if (result.success) {
  const tdfArchive = result.data; // Base64-encoded TDF
  console.log('TDF created:', tdfArchive);

  // Read the TDF manifest
  const manifestResult = tdf_read(tdfArchive);
  if (manifestResult.success) {
    const manifest = JSON.parse(manifestResult.data);
    console.log('Manifest:', manifest);
  }
} else {
  console.error('Error:', result.error);
}
```

### Node.js

```javascript
const { tdf_create, tdf_read, access_evaluate, version } = require('@arkavo-org/opentdf-wasm');

console.log('OpenTDF WASM version:', version());

// Create a TDF
const data = Buffer.from('Sensitive information').toString('base64');
const policy = {
  uuid: require('crypto').randomUUID(),
  body: {
    attributes: [],
    dissem: ['user@example.com']
  }
};

const result = tdf_create(
  data,
  'https://kas.example.com',
  JSON.stringify(policy)
);

if (result.success) {
  const tdfArchive = result.data;
  console.log('TDF created successfully');

  // Read the TDF manifest
  const manifestResult = tdf_read(tdfArchive);
  if (manifestResult.success) {
    const manifest = JSON.parse(manifestResult.data);
    console.log('Manifest:', manifest);
  }
} else {
  console.error('Error:', result.error);
}
```

### Attribute-Based Access Control (ABAC)

```javascript
// Define an attribute policy
const policy = {
  type: "Condition",
  attribute: {
    namespace: "gov.example",
    name: "clearance"
  },
  operator: "MinimumOf",
  value: "SECRET"
};

// User attributes
const userAttributes = {
  "gov.example:clearance": "TOP_SECRET",
  "gov.example:department": "ENGINEERING"
};

// Evaluate access
const accessResult = access_evaluate(
  JSON.stringify(policy),
  JSON.stringify(userAttributes)
);

if (accessResult.success) {
  const granted = accessResult.data === 'true';
  console.log('Access granted:', granted);
} else {
  console.error('Evaluation error:', accessResult.error);
}
```

### Complex ABAC Policies

```javascript
// Create a policy requiring both clearance and department
const complexPolicy = {
  type: "And",
  conditions: [
    {
      type: "Condition",
      attribute: {
        namespace: "gov.example",
        name: "clearance"
      },
      operator: "MinimumOf",
      value: "SECRET"
    },
    {
      type: "Condition",
      attribute: {
        namespace: "gov.example",
        name: "department"
      },
      operator: "In",
      value: ["ENGINEERING", "EXECUTIVE"]
    }
  ]
};

// Create TDF with ABAC policy
const fullPolicy = {
  uuid: crypto.randomUUID(),
  body: {
    attributes: [complexPolicy],
    dissem: ['user@example.com']
  }
};

const result = tdf_create(
  btoa('Classified data'),
  'https://kas.example.com',
  JSON.stringify(fullPolicy)
);
```

## API Reference

### `version(): string`

Returns the version of the OpenTDF WASM library.

### `tdf_create(data: string, kas_url: string, policy_json: string): WasmResult`

Creates a TDF archive with encrypted data.

**Parameters:**
- `data`: Base64-encoded data to encrypt
- `kas_url`: KAS (Key Access Service) URL
- `policy_json`: JSON string containing the policy

**Returns:** `WasmResult` with base64-encoded TDF archive in `data` field

### `tdf_read(tdf_data: string): WasmResult`

Reads a TDF archive and returns its manifest.

**Parameters:**
- `tdf_data`: Base64-encoded TDF archive

**Returns:** `WasmResult` with JSON manifest in `data` field

### `policy_create(policy_json: string): WasmResult`

Creates and validates a policy from JSON.

**Parameters:**
- `policy_json`: JSON string containing policy definition

**Returns:** `WasmResult` with validated policy JSON in `data` field

### `access_evaluate(policy_json: string, attributes_json: string): WasmResult`

Evaluates an attribute-based access control policy.

**Parameters:**
- `policy_json`: JSON string containing the attribute policy
- `attributes_json`: JSON string containing user attributes as key-value pairs

**Returns:** `WasmResult` with boolean string ("true"/"false") in `data` field

### `attribute_identifier_create(identifier: string): WasmResult`

Creates an attribute identifier from namespace:name format.

**Parameters:**
- `identifier`: String in format "namespace:name"

**Returns:** `WasmResult` with JSON attribute identifier in `data` field

### `WasmResult`

All functions return a `WasmResult` object with the following properties:

- `success: boolean` - Whether the operation succeeded
- `data: string | null` - Result data if successful
- `error: string | null` - Error message if failed

## Building from Source

### Prerequisites

- Rust 1.70 or later
- wasm-pack (`cargo install wasm-pack`)

### Build for Web

```bash
cd crates/wasm
wasm-pack build --target web --out-dir pkg-web
```

### Build for Node.js

```bash
cd crates/wasm
wasm-pack build --target nodejs --out-dir pkg-node
```

### Build both targets

```bash
npm run build
```

## Testing

```bash
wasm-pack test --headless --firefox
```

## Size Optimization

The WASM binary is optimized for size using:
- `opt-level = "z"` - Optimize for size
- `lto = true` - Link-time optimization
- `codegen-units = 1` - Single codegen unit for better optimization

Typical bundle sizes:
- Web: ~200KB (gzipped)
- Node.js: ~250KB (gzipped)

## Browser Compatibility

- Chrome/Edge: 84+
- Firefox: 79+
- Safari: 15+
- All browsers with WebAssembly support

## Node.js Compatibility

- Node.js 14+ with WebAssembly support

## Security Considerations

- All cryptographic operations use the same secure primitives as the native Rust library
- Random number generation uses the browser's `crypto.getRandomValues()` or Node.js `crypto.randomBytes()`
- Memory is automatically managed by WebAssembly
- Sensitive data should be cleared from JavaScript variables after use

## License

Apache-2.0

## Contributing

See the main [OpenTDF-RS repository](https://github.com/arkavo-org/opentdf-rs) for contribution guidelines.
