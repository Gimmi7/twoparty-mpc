import com.alibaba.fastjson2.JSON;
import twoparty.mpc.MpcTypes;
import twoparty.mpc.NativeMpc;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class Secp256k1Test {

    public static void main(String[] args) {
        Path currentPath = Paths.get("");
        String workspacePath = currentPath.toAbsolutePath().toString();
        System.out.println("Current Path: " + workspacePath);
        String libPath = workspacePath + "/target/debug/libtwoparty_client.dylib";
        System.load(libPath);

        // keygen
        String identity_id = "wangcy";
        String ws_url = "ws://localhost:8822/ws";
        byte[][] keygen_result = NativeMpc.secp256k1Keygen(identity_id, ws_url);
        if (keygen_result.length == 2) {
            throw new RuntimeException(new String(keygen_result[1]));
        }
        byte[] share_bytes = keygen_result[0];
        MpcTypes.SavedShare savedShare = JSON.parseObject(share_bytes, MpcTypes.SavedShare.class);
        System.out.printf("identity_id=%s, party=%d, scope=%d, share_id=%s \n",
                savedShare.identity_id, savedShare.party, savedShare.scope, savedShare.share_id);


        // sign
        byte[] message_digest = "hello".getBytes();
        byte[][] sign_result = NativeMpc.secp256k1Sign(ws_url, share_bytes, message_digest);
        if (sign_result.length == 2) {
            throw new RuntimeException(new String(sign_result[1]));
        }
        byte[] sig_bytes = sign_result[0];
        MpcTypes.Secp256k1Sig sig = JSON.parseObject(sig_bytes, MpcTypes.Secp256k1Sig.class);
        System.out.println(JSON.toJSONString(sig));

        // rotate
        byte[][] rotate_result = NativeMpc.secp256k1Rotate(ws_url, share_bytes);
        if (rotate_result.length == 2) {
            throw new RuntimeException(new String(rotate_result[1]));
        }
        byte[] new_share_bytes = rotate_result[0];
        MpcTypes.SavedShare new_share = JSON.parseObject(new_share_bytes, MpcTypes.SavedShare.class);
        System.out.printf("identity_id=%s, party=%d, scope=%d, share_id=%s \n",
                new_share.identity_id, new_share.party, new_share.scope, new_share.share_id);
        // check public_key consistence, no need to do this, library has checked
        if (!Arrays.equals(savedShare.uncompressed_pub, new_share.uncompressed_pub)) {
            throw new RuntimeException("public_key not consistent");
        }

        // export
        byte[][] export_result = NativeMpc.secp256k1Export(ws_url, new_share_bytes);
        if (export_result.length == 2) {
            throw new RuntimeException(new String(export_result[1]));
        }
        byte[] x_bytes = export_result[0];
        String hex_encoded_x = new String(x_bytes);
        System.out.println("exported private key x=" + hex_encoded_x);
    }
}
