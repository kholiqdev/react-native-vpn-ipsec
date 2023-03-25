import { NativeEventEmitter, NativeModules, EmitterSubscription, Platform } from 'react-native';

// the generic VPN state for all platforms.
export enum VpnState {
  invalid,
  disconnected,
  connecting,
  connected,
  reasserting,
  disconnecting,
}

/// the error state from `VpnStateService`.
/// only available for Android device.
export enum CharonErrorState {
  NO_ERROR,
  AUTH_FAILED,
  PEER_AUTH_FAILED,
  LOOKUP_FAILED,
  UNREACHABLE,
  GENERIC_ERROR,
  PASSWORD_MISSING,
  CERTIFICATE_UNAVAILABLE,
  UNDEFINED,
}

const stateChanged: NativeEventEmitter = new NativeEventEmitter(NativeModules.RNIpSecVpn);

// receive state change from VPN service.
export const STATE_CHANGED_EVENT_NAME: string = 'stateChanged';

// remove change listener
export const removeOnStateChangeListener: (stateChangedEvent: EmitterSubscription) => void = (stateChangedEvent) => {
  stateChangedEvent.remove();
};

// set a change listener
export const onStateChangedListener: (
  callback: (state: { state: VpnState; charonState: CharonErrorState }) => void
) => EmitterSubscription = (callback) => {
  return stateChanged.addListener(STATE_CHANGED_EVENT_NAME, (e: { state: VpnState; charonState: CharonErrorState }) => callback(e));
};

// prepare for vpn connection.
//
// android:
//   for first connection it will show a dialog to ask for permission.
//   when your connection was interrupted by another VPN connection,
//   you should prepare again before reconnect.
//   also if activity isn't running yet,
//   the activity can be null and will raise an exception
//   in this case prepare should be called once again when the activity is running.
//
// ios:
//   create a watch for state change
//   does not raise anything
export const prepare: () => Promise<void> = NativeModules.RNIpSecVpn.prepare;

// connect to VPN.

export enum NEVPNIKEv2CertificateType {
  RSA = 1,
  ECDSA256 = 2,
  ECDSA384 = 3,
  ECDSA521 = 4,
  ed25519 = 5
}

export interface NEVPNIKEv2SecurityAssociationParameters {

  /**
   *case algorithmDES = 1
  case algorithm3DES = 2
  case algorithmAES128 = 3
  case algorithmAES256 = 4
  case algorithmAES128GCM = 5
  case algorithmAES256GCM = 6
  case algorithmChaCha20Poly1305 = 7
   *
   * @type {number}
   * @memberof NEVPNIKEv2SecurityAssociationParameters
   */
  encryptionAlgorithm: number

  /**
   *case SHA96 = 1
case SHA160 = 2
case SHA256 = 3
case SHA384 = 4
case SHA512 = 5
   *
   * @type {number}
   * @memberof NEVPNIKEv2SecurityAssociationParameters
   */
  integrityAlgorithm: number
  /**
   *case groupInvalid = 0
case group1 = 1
case group2 = 2
case group5 = 5
case group14 = 14
case group15 = 15
case group16 = 16
case group17 = 17
case group18 = 18
case group19 = 19
case group20 = 20
case group21 = 21
case group31 = 31
   *
   * @type {number}
   * @memberof NEVPNIKEv2SecurityAssociationParameters
   */
  diffieHellmanGroup: number


  lifetimeMinutes: number


}

export interface VPNConfigOptions {
  name: string
  type: "ipsec" | "ikev2"
  /**
   * case none = 0
    case certificate = 1
    case sharedSecret = 2
   */
  authenticationMethod: number
  address: string
  username: string
  password: string
  secret?: string
  remoteIdentifier?: string
  localIdentifier?: string
  /* config options for ikev2 vpn type */
  certificateType?: NEVPNIKEv2CertificateType
  ikeSecurityAssociationParameters?: NEVPNIKEv2SecurityAssociationParameters
  childSecurityAssociationParameters?: NEVPNIKEv2SecurityAssociationParameters

}

export const connect: (
  config: VPNConfigOptions,
  address: string,
  username: string,
  password: string,
  secret: string,
  disapleOnSleep: boolean
) => Promise<void> = (name, address, username, password, secret, disapleOnSleep) => {
  if (Platform.OS == 'ios') {
    return NativeModules.RNIpSecVpn.connect(name, address || '', username || '', password || '', secret || '', disapleOnSleep);
  } else {
    return NativeModules.RNIpSecVpn.connect(address || '', username || '', password || '');
  }
};

export const saveConfig: (config: VPNConfigOptions, address: string, username: string, password: string, secret: string) => Promise<void> = (
  config,
  address,
  username,
  password,
  secret
) => {
  if (Platform.OS == 'ios') {
    return NativeModules.RNIpSecVpn.saveConfig(config, address || '', username || '', password || '', secret || '');
  } else {
    return NativeModules.RNIpSecVpn.connect(address || '', username || '', password || '');
  }
};

// get current state
export const getCurrentState: () => Promise<VpnState> = NativeModules.RNIpSecVpn.getCurrentState;

export const getConnectionTimeSecond: () => Promise<Number> = NativeModules.RNIpSecVpn.getConnectionTimeSecond;

// get current error state from `VpnStateService`. (Android only will recieve no error on ios)
// when [VpnState.genericError] is receivedon android, details of error can be
// inspected by [CharonErrorState].
export const getCharonErrorState: () => Promise<CharonErrorState> = NativeModules.RNIpSecVpn.getCharonErrorState;

// disconnect and stop VPN service.
// does not raise any exception
export const disconnect: () => Promise<void> = NativeModules.RNIpSecVpn.disconnect;

export default NativeModules.RNIpSecVpn;
