import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.text.SimpleDateFormat;
import java.util.*;

public class SecureVaultManager {
    private static final String LOG_FILE = "vault_log.txt";
    private static final Set<String> SKIP_NAMES = new HashSet<>(Arrays.asList(LOG_FILE, ".git", "node_modules"));
    private static final int BUFFER_SIZE = 8192;
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12; // recommended for GCM
    private static final int ITERATIONS = 65536;
    private static final int KEY_LEN = 256;

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("? SecureVaultManager (AES-GCM, PBKDF2) ?");
        System.out.print("Enter folder path: ");
        String path = sc.nextLine().trim();
        System.out.print("Enter password: ");
        String password = sc.nextLine();

        if (password.isEmpty()) {
            System.out.println("Password cannot be empty. Exiting.");
            return;
        }

        File folder = new File(path);
        if (!folder.exists() || !folder.isDirectory()) {
            System.out.println("Invalid folder.");
            return;
        }

        System.out.println("1. Encrypt\n2. Decrypt");
        int choice;
        try {
            choice = Integer.parseInt(sc.nextLine().trim());
        } catch (NumberFormatException e) {
            System.out.println("Invalid choice.");
            return;
        }

        boolean encrypt = (choice == 1);
        try {
            processFolder(folder.toPath(), password, encrypt);
            System.out.println("Done. Check " + LOG_FILE + " for details.");
        } catch (IOException e) {
            System.out.println("Operation failed: " + e.getMessage());
        }
    }

    private static void processFolder(Path folder, String password, boolean encrypt) throws IOException {
        Files.walk(folder)
            .filter(p -> !Files.isDirectory(p))
            .forEach(p -> {
                try {
                    Path name = p.getFileName();
                    if (name != null && SKIP_NAMES.contains(name.toString())) {
                        logAction(p.toString(), "SKIPPED");
                        return;
                    }
                    if (encrypt) {
                        encryptFile(p, password);
                        logAction(p.toString(), "ENCRYPTED");
                    } else {
                        decryptFile(p, password);
                        logAction(p.toString(), "DECRYPTED");
                    }
                } catch (AEADBadTagException e) {
                    System.out.println("Authentication failed (wrong password?) for: " + p);
                    logAction(p.toString(), "AUTH_FAILED");
                } catch (Exception e) {
                    System.out.println("Error processing: " + p + " -> " + e.getMessage());
                    logAction(p.toString(), "ERROR: " + e.getMessage());
                }
            });
    }

    private static void encryptFile(Path file, String password) throws Exception {
        // Generate salt and IV
        byte[] salt = secureRandomBytes(SALT_LEN);
        byte[] iv = secureRandomBytes(IV_LEN);

        SecretKey key = deriveKey(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        Path tmp = Files.createTempFile(file.getParent(), "enc-", ".tmp");
        try (OutputStream fos = Files.newOutputStream(tmp);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher);
             InputStream fis = Files.newInputStream(file)) {

            // Write header: salt + iv (so we can derive key on decrypt)
            fos.write(salt);
            fos.write(iv);

            byte[] buffer = new byte[BUFFER_SIZE];
            int r;
            while ((r = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, r);
            }
        }

        // Replace original with encrypted file atomically if possible
        atomicReplace(tmp, file);
    }

    private static void decryptFile(Path file, String password) throws Exception {
        // Read salt and iv from the file header
        try (InputStream fis = Files.newInputStream(file)) {
            byte[] salt = new byte[SALT_LEN];
            byte[] iv = new byte[IV_LEN];

            int readSalt = fis.read(salt);
            int readIv = fis.read(iv);
            if (readSalt != SALT_LEN || readIv != IV_LEN) {
                throw new IOException("File not encrypted with this tool or file too small: " + file);
            }

            SecretKey key = deriveKey(password.toCharArray(), salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            Path tmp = Files.createTempFile(file.getParent(), "dec-", ".tmp");
            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 OutputStream fos = Files.newOutputStream(tmp)) {

                byte[] buffer = new byte[BUFFER_SIZE];
                int r;
                while ((r = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, r);
                }
            }

            atomicReplace(tmp, file);
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LEN);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] secureRandomBytes(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static void atomicReplace(Path src, Path target) throws IOException {
        try {
            Files.move(src, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ex) {
            // Fallback if atomic move not supported
            Files.move(src, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static synchronized void logAction(String filePath, String action) {
        String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        String line = time + " - " + action + ": " + filePath + System.lineSeparator();
        try {
            Files.write(Paths.get(LOG_FILE), line.getBytes("UTF-8"), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.out.println("Failed to write log: " + e.getMessage());
        }
    }
}