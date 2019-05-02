
# React Native Status Keycard [![npm version](https://badge.fury.io/js/react-native-status-keycard.svg)](https://badge.fury.io/js/react-native-status-keycard)

React Native library to interact with [Keycard](https://keycard.status.im/) using [Java SDK](https://github.com/status-im/status-keycard-java)


## Getting started

`$ npm install react-native-status-keycard --save`

### Mostly automatic installation

`$ react-native link react-native-status-keycard`

### Manual installation

Android is the only platform supported by now.

#### Android

1. Open up `android/app/src/main/java/[...]/MainActivity.java`
  - Add `import com.reactlibrary.RNStatusKeycardPackage;` to the imports at the top of the file
  - Add `new RNStatusKeycardPackage()` to the list returned by the `getPackages()` method
2. Append the following lines to `android/settings.gradle`:
  	```
  	include ':react-native-status-keycard'
  	project(':react-native-status-keycard').projectDir = new File(rootProject.projectDir, 	'../node_modules/react-native-status-keycard/android')
  	```
3. Insert the following lines inside the dependencies block in `android/app/build.gradle`:
  	```
      compile project(':react-native-status-keycard')
  	```

## Usage

Take a look into [docs](./docs/usage.md)

For more usage examples, please refer to https://github.com/status-im/status-react (assuming you can read Clojure)
For Keycard API documention, please look into https://status.im/keycard_api/
  