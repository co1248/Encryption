import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.Cipher;

/**
 * 
 * @author co1248
 * @Date : 2021-12-01
 */
public class RSATEST {
	static final int KEY_SIZE = 2048;

	public static void main(String[] args) {
		HashMap<String, String> rsaKeyPair = createKeypairAsString();
		String publicKey = rsaKeyPair.get("publicKey");
		String privateKey = rsaKeyPair.get("privateKey");
		int menu;

		System.out.println("만들어진 공개키:" + publicKey);
		System.out.println("만들어진 개인키:" + privateKey);
		Scanner sc = new Scanner(System.in);
		while (true) {
			System.out.println("메뉴선택 : 1.암호화 2.복호화 (이외의 값 종료)");
			menu = sc.nextInt();
			if (menu != 1 && menu != 2) {
				System.out.println("종료합니다.");
				break;
			}

			if (menu == 1) {
				System.out.println("평문을 입력하세요.(공개키 자동 사용)");
				String plainText = sc.next();
				System.out.println("평문: " + plainText);

				String encryptedText = encode(plainText, publicKey);
				System.out.println("암호화: " + encryptedText);
			}
			if (menu == 2) {
				System.out.println("암호문을 입력하세요.");
				String encryptedText = sc.next();
				System.out.println("암호문: " + encryptedText);

				// System.out.println("개인키를 입력하세요.");
				// String inputPrivateKey = sc.next();

				String decryptedText = decode(encryptedText, privateKey/* , inputPrivateKey */);
				System.out.println("복호화: " + decryptedText);
			}
		}
		sc.close();
	}

	// 키페어 생성
	static HashMap<String, String> createKeypairAsString() {
		HashMap<String, String> stringKeypair = new HashMap<>();
		try {
			SecureRandom secureRandom = new SecureRandom();
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(KEY_SIZE, secureRandom);
			KeyPair keyPair = keyPairGenerator.genKeyPair();

			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();

			String stringPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
			String stringPrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());

			stringKeypair.put("publicKey", stringPublicKey);
			stringKeypair.put("privateKey", stringPrivateKey);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return stringKeypair;
	}

	// 암호화
	static String encode(String plainData, String stringPublicKey) {
		String encryptedData = null;
		try {
			// 평문으로 전달받은 공개키를 공개키객체로 만드는 과정
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] bytePublicKey = Base64.getDecoder().decode(stringPublicKey.getBytes());
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

			// 만들어진 공개키객체를 기반으로 암호화모드로 설정하는 과정
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);

			// 평문을 암호화하는 과정
			byte[] byteEncryptedData = cipher.doFinal(plainData.getBytes());
			encryptedData = Base64.getEncoder().encodeToString(byteEncryptedData);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedData;
	}

	// 복호화
	// @param inputPrivateKey
	static String decode(String encryptedData, String stringPrivateKey/* , String inputPrivateKey */) {
		String decryptedData = null;
		try {
			// 평문으로 전달받은 개인키를 개인키객체로 만드는 과정
			// if (inputPrivateKey != stringPrivateKey) { //개인키 틀렸을 시
			// System.out.println("The private key is not supported"); } else {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] bytePrivateKey = Base64.getDecoder().decode(stringPrivateKey.getBytes());
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

			// 만들어진 개인키객체를 기반으로 암호화모드로 설정하는 과정
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			// 암호문을 평문화하는 과정
			byte[] byteEncryptedData = Base64.getDecoder().decode(encryptedData.getBytes());
			byte[] byteDecryptedData = cipher.doFinal(byteEncryptedData);
			decryptedData = new String(byteDecryptedData);
			// }
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decryptedData;
	}
}