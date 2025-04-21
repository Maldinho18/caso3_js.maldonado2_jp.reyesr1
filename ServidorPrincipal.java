import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class ServidorPrincipal {
    private static Map<Integer, String[]> servicios = new HashMap<>();
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    public static void main(String[] args){
        try {
            servicios.put(1, new String[]{"192.168.1.10", "8080"});
            servicios.put(2, new String[]{"192.168.1.11", "8081"});
            servicios.put(3, new String[]{"192.168.1.12", "8082"});

            privateKey = CryptoUtils.loadPrivateKey("private.key");
            publicKey = CryptoUtils.loadPublicKey("public.key");

            ServerSocket serverSocket = new ServerSocket(9000);
            System.out.println("Servidor Principal iniciado en el puerto 9000");

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("Cliente conectado: " + socket.getInetAddress());
                new Thread(new ServicioDelegado(socket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class ServicioDelegado implements Runnable {
        private Socket socket;

        public ServicioDelegado(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try (
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            ) {
                DHParameterSpec dhSpec = (DHParameterSpec)CryptoUtils.generarDHParameterSpec();
                out.writeUTF(dhSpec.getP().toString());
                out.writeUTF(String.valueOf(dhSpec.getG()));
                KeyPair serverDPHPair = CryptoUtils.generarDHKeyPair(dhSpec);
                byte[] serverDHPubEnc = serverDPHPair.getPublic().getEncoded();
                out.writeInt(serverDHPubEnc.length);
                out.write(serverDHPubEnc);

                int clientDHPubLen = in.readInt();
                byte[] clientDHPubEnc = new byte[clientDHPubLen];
                in.readFully(clientDHPubEnc);
                KeyFactory keyFactory = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientDHPubEnc);
                PublicKey clientDHPubKey = keyFactory.generatePublic(x509KeySpec);

                byte[] sharedSecret = CryptoUtils.generarSecretoCompartido(serverDPHPair.getPrivate(), clientDHPubKey);
                byte[] digest = CryptoUtils.computeSHA512(sharedSecret);
                SecretKey[] sessionKeys = CryptoUtils.deriveSessionKeys(digest);
                SecretKey aesKey = sessionKeys[0];
                SecretKey hmacKey = sessionKeys[1];

                IvParameterSpec iv = CryptoUtils.generateIV();
                out.writeInt(iv.getIV().length);
                out.write(iv.getIV());

                StringBuilder sb = new StringBuilder();
                for (Map.Entry<Integer, String[]> entry : servicios.entrySet()) {
                    sb.append(entry.getKey()).append(",").append(entry.getValue()[0]).append(",").append(entry.getValue()[1]).append(";");
                }
                byte[] tablaBytes = sb.toString().getBytes("UTF-8");

                long startSign = System.nanoTime();
                byte[] signature = CryptoUtils.signData(tablaBytes, privateKey);
                long endSign = System.nanoTime();
                long tiempoFirma = endSign - startSign;

                long startEnc = System.nanoTime();
                byte[] tablaCifrada = CryptoUtils.aesEncriptar(tablaBytes, aesKey, iv);
                long endEnc = System.nanoTime();
                long tiempoCifrado = endEnc - startEnc;

                byte[] hmacTabla = CryptoUtils.calcularHMAC(tablaCifrada, hmacKey);

                out.writeInt(signature.length);
                out.write(signature);
                out.writeInt(tablaCifrada.length);
                out.write(tablaCifrada);
                out.writeInt(hmacTabla.length);
                out.write(hmacTabla);

                System.out.println("Tabla de servicios enviada. Tiempos (ns): Firma: " + tiempoFirma + ", Cifrado: " + tiempoCifrado);

                int servicioId = in.readInt();
                int receivedHmacLen = in.readInt();
                byte[] receivedHmac = new byte[receivedHmacLen];
                in.readFully(receivedHmac);

                byte[] consultaBytes = String.valueOf(servicioId).getBytes("UTF-8");

                long startVerify = System.nanoTime();
                if(!CryptoUtils.verificarHMAC(consultaBytes, hmacKey, receivedHmac)) {
                    System.out.println("HMAC no coincide. Solicitud rechazada.");
                    out.writeUTF("HMAC no coincide. Solicitud rechazada.");
                    return;
                }
                long endVerify = System.nanoTime();
                long tiempoVerificacion = endVerify - startVerify;

                String[] datosServicio = servicios.getOrDefault(servicioId, new String[] { "-1", "-1"});
                String respuesta = datosServicio[0] + "," + datosServicio[1];
                byte[] respuestaBytes = respuesta.getBytes("UTF-8");

                byte[] respuestaCifrada = CryptoUtils.aesEncriptar(respuestaBytes, aesKey, iv);
                byte[] hmacRespuesta = CryptoUtils.calcularHMAC(respuestaCifrada, hmacKey);

                out.writeInt(respuestaCifrada.length);
                out.write(respuestaCifrada);
                out.writeInt(hmacRespuesta.length);
                out.write(hmacRespuesta);

                System.out.println("Consulta Procesada. Tiempo de verificación (ns): " + tiempoVerificacion);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try { socket.close(); } catch (IOException ioe) {}
            }
        }
    }
}