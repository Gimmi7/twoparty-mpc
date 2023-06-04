package twoparty.mpc;

import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) {
        String property = System.getProperty("java.library.path");
        System.out.println(property);

        Path currentPath = Paths.get("");
        String workspacePath = currentPath.toAbsolutePath().toString();
        System.out.println("Current Path: " + workspacePath);
        String libPath = workspacePath + "/target/debug/libtwoparty_client.dylib";

        System.load(libPath);

        NativeMpc.ecdsaKeygen();
    }
}