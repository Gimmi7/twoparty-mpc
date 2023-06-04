package twoparty.mpc;

import java.util.Arrays;

public class NativeMpc {

    public static native byte[][] seec256k1Keygen(String identity_id, String ws_url);

}
