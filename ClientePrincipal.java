import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class ClientePrincipal {

    public static PublicKey serverPublicKey;

    public static void main(String[] args) throws Exception {
        serverPublicKey = CryptoUtils.loadPublicKey("public.key");

        if (args.length == 2 && args[0].equalsIgnoreCase("iterative")) {
            int numIter = Integer.parseInt(args[1]);
            for (int i = 1; i <= numIter; i++) {
                System.out.println("=== Iteración " + i + " ===");
                realizarUnaConsulta();
            }
            return;
        }

        if (args.length == 2 && args[0].equalsIgnoreCase("concurrent")) {
            int nClients = Integer.parseInt(args[1]);
            ExecutorService pool = Executors.newFixedThreadPool(nClients);
            for (int i = 0; i < nClients; i++) {
                pool.submit(() -> {
                    try {
                        realizarUnaConsulta();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
            pool.shutdown();
            pool.awaitTermination(5, TimeUnit.MINUTES);
            return;
        }

        realizarUnaConsulta();
    }

    private static void realizarUnaConsulta() throws Exception {
        try (Socket socket = new Socket("localhost", 9000);
             DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            BigInteger p = new BigInteger(in.readUTF());
            BigInteger g = new BigInteger(in.readUTF());
            DHParameterSpec dhSpec = new DHParameterSpec(p, g);

            int lenS = in.readInt();
            byte[] pubS = new byte[lenS];
            in.readFully(pubS);
            PublicKey serverDHPubKey = KeyFactory.getInstance("DH")
                    .generatePublic(new X509EncodedKeySpec(pubS));

            KeyPair clientDHPair = CryptoUtils.generarDHKeyPair(dhSpec);
            byte[] clientDHPubEnc = clientDHPair.getPublic().getEncoded();
            out.writeInt(clientDHPubEnc.length);
            out.write(clientDHPubEnc);

            byte[] sharedSecret = CryptoUtils.generarSecretoCompartido(
                    clientDHPair.getPrivate(),
                    serverDHPubKey);
            byte[] digest = CryptoUtils.computeSHA512(sharedSecret);
            SecretKey[] sessionKeys = CryptoUtils.deriveSessionKeys(digest);
            SecretKey aesKey = sessionKeys[0];
            SecretKey hmacKey = sessionKeys[1];

            // Recibir y verificar tabla de servicios
            int ivLen = in.readInt();
            byte[] ivTab = new byte[ivLen];
            in.readFully(ivTab);
            IvParameterSpec iv = new IvParameterSpec(ivTab);

            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            int tablaCifLen = in.readInt();
            byte[] tablaCif = new byte[tablaCifLen];
            in.readFully(tablaCif);

            int hmacLen = in.readInt();
            byte[] hmacTabla = new byte[hmacLen];
            in.readFully(hmacTabla);

            long startSign = System.nanoTime(); // se mide en servidor, no aquí
            if (!CryptoUtils.verificarHMAC(tablaCif, hmacKey, hmacTabla)) {
                System.out.println("Error: HMAC no coincide.");
                return;
            }

            byte[] tablaDes = CryptoUtils.aesDesencriptar(tablaCif, aesKey, iv);
            if (!CryptoUtils.verificarSignature(tablaDes, signature, serverPublicKey)) {
                System.out.println("Error: Firma no coincide.");
                return;
            }

            String tablaServicios = new String(tablaDes, "UTF-8");
            System.out.println("Tabla de servicios: " + tablaServicios);

            // Seleccionar servicio aleatoriamente
            String[] ent = tablaServicios.split(";");
            List<Integer> ids = new ArrayList<>();
            for (String e : ent)
                if (!e.isEmpty())
                    ids.add(Integer.parseInt(e.split(",")[0]));
            int svc = ids.get(new Random().nextInt(ids.size()));
            System.out.println("ID del servicio seleccionado: " + svc);

            out.writeInt(svc);
            byte[] hmacConsulta = CryptoUtils.calcularHMAC(
                    String.valueOf(svc).getBytes("UTF-8"), hmacKey);
            out.writeInt(hmacConsulta.length);
            out.write(hmacConsulta);

            int ivRespLen = in.readInt();
            byte[] ivResp = new byte[ivRespLen];
            in.readFully(ivResp);
            IvParameterSpec ivRespSpec = new IvParameterSpec(ivResp);

            int respCifLen = in.readInt();
            byte[] respCif = new byte[respCifLen];
            in.readFully(respCif);

            int respHmacLen = in.readInt();
            byte[] respHmac = new byte[respHmacLen];
            in.readFully(respHmac);

            if (!CryptoUtils.verificarHMAC(respCif, hmacKey, respHmac)) {
                System.out.println("Error: HMAC de la respuesta no coincide.");
                return;
            }

            byte[] respDes = CryptoUtils.aesDesencriptar(respCif, aesKey, ivRespSpec);
            String resp = new String(respDes, "UTF-8");

            System.out.println("Respuesta del servidor: " + resp);
        }
    }
}



