package twoparty.mpc;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        String property = System.getProperty("java.library.path");
        System.out.println(property);

        Path currentPath = Paths.get("");
        String workspacePath = currentPath.toAbsolutePath().toString();
        System.out.println("Current Path: " + workspacePath);
        String libPath = workspacePath + "/target/debug/libtwoparty_client.dylib";

        System.load(libPath);

        String identity_id = "wangcy";
        String ws_url = "ws://localhost:8822/ws";
        byte[][] result = NativeMpc.seec256k1Keygen(identity_id, ws_url);
        if (result.length == 2) {
            System.out.println(new String(result[1]));
            return;
        }
        System.out.println(Arrays.toString(result[0]));
    }
}