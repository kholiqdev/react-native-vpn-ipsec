import { NativeEventEmitter, NativeModules, Platform } from 'react-native';
// the generic VPN state for all platforms.
export var VpnState;
(function (VpnState) {
    VpnState[VpnState["invalid"] = 0] = "invalid";
    VpnState[VpnState["disconnected"] = 1] = "disconnected";
    VpnState[VpnState["connecting"] = 2] = "connecting";
    VpnState[VpnState["connected"] = 3] = "connected";
    VpnState[VpnState["reasserting"] = 4] = "reasserting";
    VpnState[VpnState["disconnecting"] = 5] = "disconnecting";
})(VpnState || (VpnState = {}));
/// the error state from `VpnStateService`.
/// only available for Android device.
export var CharonErrorState;
(function (CharonErrorState) {
    CharonErrorState[CharonErrorState["NO_ERROR"] = 0] = "NO_ERROR";
    CharonErrorState[CharonErrorState["AUTH_FAILED"] = 1] = "AUTH_FAILED";
    CharonErrorState[CharonErrorState["PEER_AUTH_FAILED"] = 2] = "PEER_AUTH_FAILED";
    CharonErrorState[CharonErrorState["LOOKUP_FAILED"] = 3] = "LOOKUP_FAILED";
    CharonErrorState[CharonErrorState["UNREACHABLE"] = 4] = "UNREACHABLE";
    CharonErrorState[CharonErrorState["GENERIC_ERROR"] = 5] = "GENERIC_ERROR";
    CharonErrorState[CharonErrorState["PASSWORD_MISSING"] = 6] = "PASSWORD_MISSING";
    CharonErrorState[CharonErrorState["CERTIFICATE_UNAVAILABLE"] = 7] = "CERTIFICATE_UNAVAILABLE";
    CharonErrorState[CharonErrorState["UNDEFINED"] = 8] = "UNDEFINED";
})(CharonErrorState || (CharonErrorState = {}));
const stateChanged = new NativeEventEmitter(NativeModules.RNIpSecVpn);
// receive state change from VPN service.
export const STATE_CHANGED_EVENT_NAME = 'stateChanged';
// remove change listener
export const removeOnStateChangeListener = (stateChangedEvent) => {
    stateChangedEvent.remove();
};
// set a change listener
export const onStateChangedListener = (callback) => {
    return stateChanged.addListener(STATE_CHANGED_EVENT_NAME, (e) => callback(e));
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
export const prepare = NativeModules.RNIpSecVpn.prepare;
// connect to VPN.
export var NEVPNIKEv2CertificateType;
(function (NEVPNIKEv2CertificateType) {
    NEVPNIKEv2CertificateType[NEVPNIKEv2CertificateType["RSA"] = 1] = "RSA";
    NEVPNIKEv2CertificateType[NEVPNIKEv2CertificateType["ECDSA256"] = 2] = "ECDSA256";
    NEVPNIKEv2CertificateType[NEVPNIKEv2CertificateType["ECDSA384"] = 3] = "ECDSA384";
    NEVPNIKEv2CertificateType[NEVPNIKEv2CertificateType["ECDSA521"] = 4] = "ECDSA521";
    NEVPNIKEv2CertificateType[NEVPNIKEv2CertificateType["ed25519"] = 5] = "ed25519";
})(NEVPNIKEv2CertificateType || (NEVPNIKEv2CertificateType = {}));
export const connect = (name, address, username, password, secret, disapleOnSleep) => {
    if (Platform.OS == 'ios') {
        return NativeModules.RNIpSecVpn.connect(name, address || '', username || '', password || '', secret || '', disapleOnSleep);
    }
    else {
        return NativeModules.RNIpSecVpn.connect(address || '', username || '', password || '');
    }
};
export const saveConfig = (config, address, username, password, secret) => {
    if (Platform.OS == 'ios') {
        return NativeModules.RNIpSecVpn.saveConfig(config, address || '', username || '', password || '', secret || '');
    }
    else {
        return NativeModules.RNIpSecVpn.connect(address || '', username || '', password || '');
    }
};
// get current state
export const getCurrentState = NativeModules.RNIpSecVpn.getCurrentState;
export const getConnectionTimeSecond = NativeModules.RNIpSecVpn.getConnectionTimeSecond;
// get current error state from `VpnStateService`. (Android only will recieve no error on ios)
// when [VpnState.genericError] is receivedon android, details of error can be
// inspected by [CharonErrorState].
export const getCharonErrorState = NativeModules.RNIpSecVpn.getCharonErrorState;
// disconnect and stop VPN service.
// does not raise any exception
export const disconnect = NativeModules.RNIpSecVpn.disconnect;
export default NativeModules.RNIpSecVpn;
