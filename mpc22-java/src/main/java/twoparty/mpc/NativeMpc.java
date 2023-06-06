package twoparty.mpc;

import java.util.Arrays;

public class NativeMpc {

    public static native byte[][] secp256k1Keygen(String identity_id, String ws_url);

    public static native byte[][] secp256k1Sign(String ws_url, byte[] saved_share, byte[] message_digest);

    public static native byte[][] secp256k1Rotate(String ws_url, byte[] saved_share);

    public static native byte[][] secp256k1Export(String ws_url, byte[] saved_share);
}
