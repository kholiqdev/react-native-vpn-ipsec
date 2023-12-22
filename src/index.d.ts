import { EmitterSubscription } from 'react-native';
export declare enum VpnState {
    invalid = 0,
    disconnected = 1,
    connecting = 2,
    connected = 3,
    reasserting = 4,
    disconnecting = 5
}
export declare enum CharonErrorState {
    NO_ERROR = 0,
    AUTH_FAILED = 1,
    PEER_AUTH_FAILED = 2,
    LOOKUP_FAILED = 3,
    UNREACHABLE = 4,
    GENERIC_ERROR = 5,
    PASSWORD_MISSING = 6,
    CERTIFICATE_UNAVAILABLE = 7,
    UNDEFINED = 8
}
export declare const STATE_CHANGED_EVENT_NAME: string;
export declare const removeOnStateChangeListener: (stateChangedEvent: EmitterSubscription) => void;
export declare const onStateChangedListener: (callback: (state: {
    state: VpnState;
    charonState: CharonErrorState;
}) => void) => EmitterSubscription;
export declare const prepare: () => Promise<void>;
export declare enum NEVPNIKEv2CertificateType {
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
    encryptionAlgorithm: number;
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
    integrityAlgorithm: number;
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
    diffieHellmanGroup: number;
    lifetimeMinutes: number;
}
export interface VPNConfigOptions {
    name: string;
    type: "ipsec" | "ikev2";
    /**
     * case none = 0
      case certificate = 1
      case sharedSecret = 2
     */
    authenticationMethod: number;
    address: string;
    username: string;
    password: string;
    secret?: string;
    identityData?: string;
    remoteIdentifier?: string;
    localIdentifier?: string;
    certificateType?: NEVPNIKEv2CertificateType;
    ikeSecurityAssociationParameters?: NEVPNIKEv2SecurityAssociationParameters;
    childSecurityAssociationParameters?: NEVPNIKEv2SecurityAssociationParameters;
}
export declare const connect: (config: VPNConfigOptions, address: string, username: string, password: string, secret: string, disapleOnSleep: boolean) => Promise<void>;
export declare const saveConfig: (config: VPNConfigOptions, address: string, username: string, password: string, secret: string) => Promise<void>;
export declare const getCurrentState: () => Promise<VpnState>;
export declare const getConnectionTimeSecond: () => Promise<Number>;
export declare const getCharonErrorState: () => Promise<CharonErrorState>;
export declare const disconnect: () => Promise<void>;
export declare const clearKeychainRefs: () => Promise<void>;
declare const _default: any;
export default _default;
//# sourceMappingURL=index.d.ts.map