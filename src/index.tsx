import { NativeModules } from 'react-native';

type StatusKeycardType = {
  multiply(a: number, b: number): Promise<number>;
};

const { StatusKeycard } = NativeModules;

export default StatusKeycard as StatusKeycardType;
