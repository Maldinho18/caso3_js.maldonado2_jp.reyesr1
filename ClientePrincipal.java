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

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class ClientePrincipal {

    public static PublicKey serverPublicKey;

    public static void main (String[] args) throws Exception {
        serverPublicKey = CryptoUtils.loadPublicKey("public.key");
        try (Socket socket = new Socket("localhost", 9000);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream())){
            
            BigInteger p = new BigInteger(in.readUTF()); 
            BigInteger g = new BigInteger(in.readUTF());
            DHParameterSpec dhSpec = new DHParameterSpec(p, g);

            int lenS = in.readInt();
            byte[] pubS = new byte[lenS];
            in.readFully(pubS);
            PublicKey serverDHPubKey = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(pubS));

/** 
            int serverDHPublen = in.readInt();
            byte[] serverDHPub = new byte[serverDHPublen];
            in.readFully(serverDHPub);
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverDHPub);
            PublicKey serverDHPubKey = keyFactory.generatePublic(x509KeySpec);
**/
            KeyPair clientDHPair = CryptoUtils.generarDHKeyPair(dhSpec);
            byte[] clientDHPubEnc = clientDHPair.getPublic().getEncoded();
            out.writeInt(clientDHPubEnc.length);
            out.write(clientDHPubEnc);

            byte[] sharedSecret = CryptoUtils.generarSecretoCompartido(clientDHPair.getPrivate(), serverDHPubKey);
            byte[] digest = CryptoUtils.computeSHA512(sharedSecret);
            SecretKey[] sessionKeys = CryptoUtils.deriveSessionKeys(digest);
            SecretKey aesKey = sessionKeys[0];
            SecretKey hmacKey = sessionKeys[1];

            int ivLen = in.readInt();
            byte[] ivTab = new byte[ivLen];
            in.readFully(ivTab);
            IvParameterSpec iv = new IvParameterSpec(ivTab);

            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);
            int tablaCiflen = in.readInt();
            byte[] tablaCif = new byte[tablaCiflen];
            in.readFully(tablaCif);
            int hmacLen = in.readInt();
            byte[] hmacTabla = new byte[hmacLen];
            in.readFully(hmacTabla);

            if (!CryptoUtils.verificarHMAC(tablaCif, hmacKey, hmacTabla)) {
                System.out.println("Error: HMAC no coincide.");
                socket.close();
                return;
            }

            byte[] tablaDes = CryptoUtils.aesDesencriptar(tablaCif, aesKey, iv);
            if(!CryptoUtils.verificarSignature(tablaDes, signature, serverPublicKey)) {
                System.out.println("Error: Firma no coincide.");
                socket.close();
                return;
            }
            String tablaServicios = new String(tablaDes, "UTF-8");
            System.out.println("Tabla de servicios: " + tablaServicios);

            String[] ent = tablaServicios.split(";");
            List<Integer> ids = new ArrayList<>();
            for (String e:ent) if (!e.isEmpty()) ids.add(Integer.parseInt(e.split(",")[0]));
            int svc = ids.get(new Random().nextInt(ids.size()));
            System.out.println("ID del servicio seleccionado: " + svc);
/** 
            String[] entradas = tablaServicios.split(";");
            List<Integer> ids = new ArrayList<>();
            List<String> ips = new ArrayList<>();
            List<Integer> puertos = new ArrayList<>();
            for (String e : entradas) {
                if (e.trim().isEmpty()) continue; 
                String[] campos = e.split(",");
                ids.add(Integer.parseInt(campos[0]));
                ips.add(campos[1]);
                puertos.add(Integer.parseInt(campos[2]));
            }

            Random rand = new Random();
            int i = rand.nextInt(ids.size());
            int serviciosId = ids.get(i);
            String servicioIp = ips.get(i);
            int servicioPuerto = puertos.get(i);
            System.out.println("ID del servicio seleccionado: " + serviciosId + " -> " + servicioIp + ":" + servicioPuerto);
**/

            byte[] consulta = String.valueOf(svc).getBytes("UTF-8");
            byte[] hmacConsulta = CryptoUtils.calcularHMAC(consulta, hmacKey);
            out.writeInt(svc);
            out.writeInt(hmacConsulta.length);
            out.write(hmacConsulta);

            int respCiflen = in.readInt();
            byte[] respCif = new byte[respCiflen];
            in.readFully(respCif);
            int respHmacLen = in.readInt();
            byte[] respHmac = new byte[respHmacLen];
            in.readFully(respHmac);

            if (!CryptoUtils.verificarHMAC(respCif, hmacKey, respHmac)) {
                System.out.println("Error: HMAC de la respuesta no coincide.");
                socket.close();
                return;
            }

            byte[] respDes = CryptoUtils.aesDesencriptar(respCif, aesKey, iv);
            String resp = new String(respDes, "UTF-8");
            System.out.println("Respuesta del servidor: " + resp);
            socket.close();
        } 
    }
}
