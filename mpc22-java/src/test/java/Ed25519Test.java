import com.alibaba.fastjson2.JSON;
import twoparty.mpc.MpcTypes;
import twoparty.mpc.NativeMpc;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class Ed25519Test {
    public static void main(String[] args) {
        Path currentPath = Paths.get("");
        String workspacePath = currentPath.toAbsolutePath().toString();
        System.out.println("Current Path: " + workspacePath);
        String libPath = workspacePath + "/target/debug/libtwoparty_client.dylib";
        System.load(libPath);

        // keygen
        String identity_id = "wangcy";
        String ws_url = "ws://localhost:8822/ws";
        byte[][] keygen_result = NativeMpc.ed25519Keygen(identity_id, ws_url);
        if (keygen_result.length == 2) {
            throw new RuntimeException(new String(keygen_result[1]));
        }
        byte[] share_bytes = keygen_result[0];
        MpcTypes.SavedShare savedShare = JSON.parseObject(share_bytes, MpcTypes.SavedShare.class);
        System.out.printf("identity_id=%s, party=%d, scope=%d, share_id=%s, public_key_length=%d \n",
                savedShare.identity_id, savedShare.party, savedShare.scope, savedShare.share_id, savedShare.uncompressed_pub.length);

        // sign
        byte[] message_digest = "hello ed25519".getBytes();
        byte[][] sign_result = NativeMpc.ed25519Sign(ws_url, share_bytes, message_digest);
        if (sign_result.length == 2) {
            throw new RuntimeException(new String(sign_result[1]));
        }
        byte[] sig_bytes = sign_result[0];
        System.out.println("sig bytes=" + sig_bytes.length);
        if (sig_bytes.length != 64) {
            throw new RuntimeException("ed25519 sig_bytes must be 64 bytes");
        }

        // rotate
        byte[][] rotate_result = NativeMpc.ed25519Rotate(ws_url, share_bytes);
        if (rotate_result.length == 2) {
            throw new RuntimeException(new String(rotate_result[1]));
        }
        byte[] new_share_bytes = rotate_result[0];
        MpcTypes.SavedShare new_share = JSON.parseObject(new_share_bytes, MpcTypes.SavedShare.class);
        System.out.printf("identity_id=%s, party=%d, scope=%d, share_id=%s, public_key_length=%d \n",
                new_share.identity_id, new_share.party, new_share.scope, new_share.share_id, new_share.uncompressed_pub.length);

        // sign with rotated_share
        byte[][] rotate_sign_result = NativeMpc.ed25519Sign(ws_url, new_share_bytes, message_digest);
        if (rotate_sign_result.length == 2) {
            throw new RuntimeException(new String(rotate_sign_result[1]));
        }
        byte[] rotate_sig_bytes = sign_result[0];
        System.out.println("rotate sig bytes=" + rotate_sig_bytes.length);
        if (rotate_sig_bytes.length != 64) {
            throw new RuntimeException("ed25519 sig_bytes must be 64 bytes");
        }

        // check sig is deterministic
        if (!Arrays.equals(sig_bytes, rotate_sig_bytes)) {
            throw new RuntimeException("ed25519 rotate sig is not deterministic");
        }
    }
}
