# Usage

You need to import Keycard object to interact with the card:

```javascript
import Keycard from "react-native-status-keycard";
```

### Listen to keycard connect/disconnect events

```javascript
import { DeviceEventEmitter } from 'react-native';

// Listen to connect/disconnect and nfc events
componentDidMount () {
  DeviceEventEmitter.addListener("keyCardOnConnected", () => console.log("keycard connected"));
  DeviceEventEmitter.addListener("keyCardOnDisconnected", () => console.log("keycard disconnected"));
  DeviceEventEmitter.addListener("keyCardOnNFCEnabled", () => console.log("nfc enabled"));
  DeviceEventEmitter.addListener("keyCardOnNFCDisabled", () => console.log("nfc disabled"));
}
```

### Errors

Library uses Promises for method calls, use `.catch` to get the error object.

Example:
```javascript
Keycard.init("123456").then(info => console.log(info)).catch(error => console.log(error))
```

Error object example:
```javascript
{"code": "EUNSPECIFIED",
"error": "Tag was lost."}
```

### Check NFC support on device
```javascript
// Check if NFC is supported by device
Keycard.nfcIsSupported().then(isSupported => isSupported ? console.log("NFC is supported") : console.log("NFC is not supported"));

// Check if NFC is enabled on device
Keycard.nfcIsEnabled().then(isEnabled => isEnabled ? console.log("NFC is enabled") : console.log("NFC is not enabled"));

// Open device NFC settings
Keycard.openNfcSettings();
```

### Get keycard information
```javascript
// If keycard was not paired before, use empty string as pairing
Keycard.getApplicationInfo("").then(info => console.log(info));

// If keycard is paired, use pairing key
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
Keycard.getApplicationInfo(pairing).then(info => console.log(info));

```

Returns object like this:
```javascript
{"free-pairing-slots": 2,
"app-version": "2.1",
"secure-channel-pub-key": "042bd559a6eb5843491f79150ccba6bcc04c5b6691079f7c7a0e2eea659960db1df67079b27fdf5df56a1092029a157c0dce7000af4d7c4c1131421623c0150d1c",
"instance-uid": "21c0ce19aa9a26efc02fd32078c08527",
"key-uid": "a88d46499e5690c6ad637e243e83cf51be3e2c67e48324b2b2def3e6a0492576",
"has-master-key?": false,
"paired?": false,
"initialized?": true}
```

`instance-uid` The instance UID of the applet. This ID never changes for the lifetime of the applet.

`key-uid` The UID of the master key on this card. Changes every time a different master key is stored. It has zero length if no key is on the card.

## Setup keycard

### Initialize the card
```javascript
const pin = "123456";
Keycard.init(pin).then(secrets => console.log(secrets));
```

`secrets` object contains PIN, PUK and Pairing password. You will need password to pair the card to device.
```javascript
{"pin": "123456",
"puk": "123456123456",
"password": "/xzPt+rEWVN3sMc5"}
```

### Pair 
Pairs keycard to device.

Use password you get after keycard initialization (using `init`):

```javascript
const password = "/xzPt+rEWVN3sMc5";
Keycard.pair(password).then(pairing => console.log(pairing));
```

`pairing` object contains pairing key as base64 string. 
You will need pairing key to open secure channel for most keycard operations. More info on pairing https://status.im/keycard_api/sdk_securechannel.html

### Generate mnemonic phrase
```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo"; 
const words = "abandon\nability\nable\nabout\n..." // bip 39 words separated by new line
Keycard.generateMnemonic(pairing, words).then(mnemonic => console.log(mnemonic));
```
`mnemonic` is a string of 12 words separated by space:
```javascript
"sure more foil soon pretty guilt run rail biology fine obey outside"
```

BIP39 words can be found here: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt

### Generate and load master key
```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const pin = "123456";
const mnemonic = "sure more foil soon pretty guilt run rail biology fine obey outside";

Keycard.generateAndLoadKey(mnemonic, pairing, pin).then(data => console.log(data));
```

`data` object returned:
```javascript
{"address": "a89a57f4d3241e6a123ea332241d6f03790075b4",
"public-key": "04cccc3998d0e0b8d56b64fad4d1f025914b8cb72558810c74dd34454fcd6907f6f7429a0726dceec9b93c9060103ff8b2e7daa1cb9a4dd62b7ae1ba2232709555",
"wallet-root-address": "b19a57f4d3241e6a123ea332241d6f03790075b4",
"wallet-root-public-key": "0427cc3998d0e0b8d56b64fad4d1f025914b8cb72558810c74dd34454fcd6907f6f7429a0726dceec9b93c9060103ff8b2e7daa1cb9a4dd62b7ae1ba2232709555",
"wallet-address": "9726cbc67d170307dd80af6416ebe844e7b8eb1c",
"wallet-public-key": "04065670509d295cb8330e02a688eafe83dbbb317486062482725ba1036dba396d635e91afd9a9e7087c0dfeaccf30d2004d092ed250d62b5c75f8bb4c9326d409",
"whisper-address": "438e576b638bff08b2872dd708cf0240811d79af",
"whisper-public-key": "04add221cb97dde8afbf3be27b0bfb3b6842071cb1052abfc3c34d45eba944dc10dcba5d4823fe69148ae17b12ed459237124365c2f46c2b46be9537ce6efa93c8",
"whisper-private-key": "073d77b952b3b92ba66947df53d03b23bc4cc8cf10cbba1060fe25a569c8ee6b",
"encryption-public-key": "04d36d64bea374b917bc097646cb4e81061c7b0ab0872207480b886e66fb52d53774e303e2aa07a1107776f312b94663566765a8a75cf0a92b0851017b28b356a1",
"instance-uid": "21c0ce19aa9a26efc02fd32078c08527",
"key-uid":"a88d46499e5690c6ad637e243e83cf51be3e2c67e48324b2b2def3e6a0492576"}
```

`address` is an address of master key `m`

`public-key` is a public key of master key `m`

`wallet-root-address` is an address of root key `m/44'/60'/0'/0`

`wallet-root-public-key` is public key of root key `m/44'/60'/0'/0`

`wallet-address` is ethereum address of key with derivation path `m/44'/60'/0'/0/0`

`whisper-address` is ethereum address of key with derivation path `m/43'/60'/1581'/0'/0`

`encryption-public-key` is public key with derivation path `m/43'/60'/1581'/1'/0`

More info about key derivation: https://status.im/keycard_api/sdk_derivation_sign.html

### Get keys from keycard
```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const pin = "123456";

Keycard.getKeys(pairing, pin).then(data => console.log(data));
```

`data` object contains:
```javascript
{"address": "a89a57f4d3241e6a123ea332241d6f03790075b4",
"public-key": "04cccc3998d0e0b8d56b64fad4d1f025914b8cb72558810c74dd34454fcd6907f6f7429a0726dceec9b93c9060103ff8b2e7daa1cb9a4dd62b7ae1ba2232709555",
"wallet-root-address": "b19a57f4d3241e6a123ea332241d6f03790075b4",
"wallet-root-public-key": "0427cc3998d0e0b8d56b64fad4d1f025914b8cb72558810c74dd34454fcd6907f6f7429a0726dceec9b93c9060103ff8b2e7daa1cb9a4dd62b7ae1ba2232709555",
"wallet-address": "9726cbc67d170307dd80af6416ebe844e7b8eb1c",
"wallet-public-key": "04065670509d295cb8330e02a688eafe83dbbb317486062482725ba1036dba396d635e91afd9a9e7087c0dfeaccf30d2004d092ed250d62b5c75f8bb4c9326d409",
"whisper-address": "438e576b638bff08b2872dd708cf0240811d79af",
"whisper-public-key": "04add221cb97dde8afbf3be27b0bfb3b6842071cb1052abfc3c34d45eba944dc10dcba5d4823fe69148ae17b12ed459237124365c2f46c2b46be9537ce6efa93c8",
"whisper-private-key": "073d77b952b3b92ba66947df53d03b23bc4cc8cf10cbba1060fe25a569c8ee6b",
"encryption-public-key": "04d36d64bea374b917bc097646cb4e81061c7b0ab0872207480b886e66fb52d53774e303e2aa07a1107776f312b94663566765a8a75cf0a92b0851017b28b356a1",
"instance-uid": "21c0ce19aa9a26efc02fd32078c08527",
"key-uid":"a88d46499e5690c6ad637e243e83cf51be3e2c67e48324b2b2def3e6a0492576"}
```

Response is identical to `generateAndLoadKey`.
Please refer to `generateAndLoadKey` response for detailed description.

### Sign
```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const pin = "123456";
const hash = "d81bbffb92157b72ceae3da72eb8224976ba42a49621822789edb0735a0e0395";

Keycard.sign(pairing, pin, hash).then(sig => console.log(sig));
```

Signature string returned. Example: ` d684afb4ec9ce59f2d112a9c9400bd04f5a5b2518b251dba4ad135448f2e75367c2ea6412893d8001ed9c9efeb7c7d37bc11f7dfcf27c4818cf0861da199de1900`

Signature consists of R, S and Recovery ID values concatenated (R+S+V). 
For example:

R: `79ef184db3150519a9719a38a7939fae39bbea088758745482cabe40127c7efb`

S: `674932db2a7a5ae4b1d9d228b3542dba83ac9ac62524a45dd984e9650ceaa736`

Recovery ID: `0`

Would produce signature: `d684afb4ec9ce59f2d112a9c9400bd04f5a5b2518b251dba4ad135448f2e75367c2ea6412893d8001ed9c9efeb7c7d37bc11f7dfcf27c4818cf0861da199de1900`

More info about signing: https://status.im/keycard_api/sdk_derivation_sign.html

### Derive key
Changes derivation path:
```javascript
const path = "m/44'/60'/0'/0/0"
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const pin = "123456";

Keycard.deriveKey(path, pairing, pin).then(path => console.log("path changed to " + path));
```
More information on key derivation: https://status.im/keycard_api/sdk_derivation_sign.html

### Remove key
Removes master key from keycard:

```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const pin = "123456";

Keycard.removeKey(pairing, pin).then(() => console.log("key removed"));
```

### Unpair

Unpairs keycard from current device:

```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const pin = "123456";

Keycard.unpair(pairing, pin).then(() => console.log("keycard unpaired"));
```

### Change PIN
```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const currentPin = "123456";
const newPin = "111111";

Keycard.removeKey(pairing, currentPin, newPin).then(() => console.log("pin changed"));
```

### Unblock PIN
When wrong PIN is entered 3 times keycard becomes blocked. You can unblock it with PUK code:
```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const puk = "123456123456";
const newPin = "111111";

Keycard.removeKey(pairing, puk, newPin).then(() => console.log("pin unblocked"));
```

### Verify PIN
Verifies PIN is valid:
```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const pin = "123456";

Keycard.removeKey(pairing, pin).then(() => console.log("pin is valid"));
```

### Delete keycard
Deletes everything from keycard including key and the applet. Dangerous operation for advanced users only. You will need to install applet again to interact with keycard.

```javascript
const pairing = "AFFdkP01GywuaJRQkGDq+OyPHBE9nECEDDCfXhpfaxlo";
const puk = "123456123456";
const newPin = "111111";

Keycard.removeKey(pairing, puk, newPin).then(() => console.log("pin unblocked"));
```

### Install applet
Keycard usually comes with installed applet. But if you have empty keycard without the applet, you can install applet with:
```javascript
Keycard.installApplet().then(() => console.log("applet installed"));
```

### Keycard CLI
You can also interact with keycard (installing and removing applet, getting card info, etc) using [keycard cli](https://github.com/status-im/keycard-cli). You'll need a USB reader for that.
