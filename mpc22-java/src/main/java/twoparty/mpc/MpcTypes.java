package twoparty.mpc;


public class MpcTypes {

    private static final int MPC_SCOPE_SECP256K1ECDSA = 1;
    private static final int MPC_SCOPE_ED25519EDDSA = 2;

    public static class SavedShare {
        public String identity_id;
        public String share_id;
        public int scope;
        public int party;
        public byte[] uncompressed_pub;
        public byte[] share_detail;
    }


    public static class Secp256k1Sig {
        // hex encoded
        public String r;
        // hex encoded
        public String s;
        public int v;
    }

    // the sig type of ed25519 is [u8;64] as described in RFC8032
}

