
import java.security.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;

public class DigitalSignature {

    private static final String ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {

            System.out.println("======================================");
            System.out.println("     ELECTRONIC SIGNATURE SYSTEM");
            System.out.println("======================================");
            System.out.println("Student: Ejebay BatyrОva");

            // 1. RSA-2048 кілттерін жасау
            KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("RSA");

            generator.initialize(2048);

            KeyPair keyPair = generator.generateKeyPair();

            System.out.println("\n[1] RSA-2048 keys generated!");

            // 2. PEM форматында кілттерді дайындау
            String publicKeyPEM = toPEM(
                    "PUBLIC KEY",
                    keyPair.getPublic().getEncoded()
            );

            String privateKeyPEM = toPEM(
                    "PRIVATE KEY",
                    keyPair.getPrivate().getEncoded()
            );

            // 3. Кілттерді сақтау
            Files.writeString(
                    Path.of("public_key.pem"),
                    publicKeyPEM
            );

            Files.writeString(
                    Path.of("private_key.pem"),
                    privateKeyPEM
            );

            System.out.println("[2] Public key saved!");
            System.out.println("[3] Private key saved!");

            // 4. Құжат мәтінін енгізу
            System.out.print("\nEnter document text: ");

            String document = scanner.nextLine();

            if (document.isBlank()) {
                document = "Electronic document. Student: Ejebay BatyrОva.";
            }

            Files.writeString(
                    Path.of("document.txt"),
                    document
            );

            System.out.println("[4] Document saved!");

            // 5. Электрондық қолтаңба жасау
            Signature signature =
                    Signature.getInstance(ALGORITHM);

            signature.initSign(keyPair.getPrivate());

            signature.update(
                    document.getBytes(StandardCharsets.UTF_8)
            );

            byte[] signedBytes = signature.sign();

            String signedText = Base64.getEncoder()
                    .encodeToString(signedBytes);

            Files.writeString(
                    Path.of("signature.sig"),
                    signedText
            );

            System.out.println("[5] Digital signature created!");
            System.out.println("Algorithm: " + ALGORITHM);

            // 6. Қолтаңбаны тексеру
            boolean verification = verifySignature(
                    document,
                    signedBytes,
                    keyPair.getPublic()
            );

            System.out.println("\n======================================");
            System.out.println("          VERIFICATION RESULT");
            System.out.println("======================================");

            System.out.println(
                    "Signature valid: " + verification
            );

            // 7. Өзгертілген құжатты тексеру
            String changedDocument = document + " CHANGED";

            boolean changedVerification = verifySignature(
                    changedDocument,
                    signedBytes,
                    keyPair.getPublic()
            );

            System.out.println(
                    "Modified document valid: "
                            + changedVerification
            );

            System.out.println("\n======================================");
            System.out.println("             SYSTEM COMPLETED");
            System.out.println("======================================");

            System.out.println("Student: Ejebay BatyrОva");

            System.out.println("\nGenerated files:");
            System.out.println("1. public_key.pem");
            System.out.println("2. private_key.pem");
            System.out.println("3. document.txt");
            System.out.println("4. signature.sig");

        } catch (Exception e) {

            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();

        }
    }

    // PEM форматын жасау
    private static String toPEM(
            String type,
            byte[] data
    ) {

        String encoded = Base64.getMimeEncoder(
                64,
                "\n".getBytes(StandardCharsets.UTF_8)
        ).encodeToString(data);

        return "-----BEGIN " + type + "-----\n"
                + encoded
                + "\n-----END " + type + "-----\n";
    }

    // Электрондық қолтаңбаны тексеру
    private static boolean verifySignature(
            String document,
            byte[] signedBytes,
            PublicKey publicKey
    ) throws Exception {

        Signature verifier =
                Signature.getInstance(ALGORITHM);

        verifier.initVerify(publicKey);

        verifier.update(
                document.getBytes(StandardCharsets.UTF_8)
        );

        return verifier.verify(signedBytes);
    }
}
