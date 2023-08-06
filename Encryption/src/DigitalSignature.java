import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.Cipher;

/**
 * 
 * @author co1248
 * @Date : 2021-12-02
 */
public class DigitalSignature {
	static final int KEY_SIZE = 2048;
	static HashMap<String, Object> rsaKeyPair = createKeypairAsString();
	static PublicKey publicKey = (PublicKey) rsaKeyPair.get("publicKey");// 형변환처리
	static PrivateKey privateKey = (PrivateKey) rsaKeyPair.get("privateKey");// 형변환처리

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		String stringpublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		String stringprivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());

		System.out.println("publicKey :" + stringpublicKey);
		System.out.println("privateKey :" + stringprivateKey);
		Scanner sc = new Scanner(System.in);
		System.out.println("평문을 입력해주세요.");
		String plainText = sc.next();
		sc.close();
		System.out.println("평문: " + plainText);
		String encryptedText = encode(plainText, publicKey);
		System.out.println("암호화: " + encryptedText);
		String decryptedText = decode(encryptedText, privateKey);
		System.out.println("복호화: " + decryptedText);
		String signText = sign(plainText, privateKey);
		System.out.println("서명: " + signText);
		boolean result = verifySignarue(plainText, signText, publicKey);
		System.out.println("인증: " + result);
	}

	// 키페어 생성
	static HashMap<String, Object> createKeypairAsString() {
		HashMap<String, Object> stringKeypair = new HashMap<>();
		try {
			// 난수생성
			SecureRandom secureRandom = new SecureRandom();
			// 지정된 다이제스트 알고리즘을 구현하는 KeyPairGenerator 객체를 작성합니다.
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			// 지정된 파라미터 세트와 난수의 발생원을 사용해 키 페어 제네레이터를 초기화합니다.
			keyPairGenerator.initialize(KEY_SIZE, secureRandom);
			// genKeyPair() 키페어 생성
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			// Returns a reference to the public key component of this key pair.
			PublicKey publicKey = keyPair.getPublic();
			// Returns a reference to the private key component of this key pair.
			PrivateKey privateKey = keyPair.getPrivate();
			// Base64 인코딩
			// String stringPublicKey =
			// Base64.getEncoder().encodeToString(publicKey.getEncoded());
			// String stringPrivateKey =
			// Base64.getEncoder().encodeToString(privateKey.getEncoded());
			// 해쉬맵에 저장
			stringKeypair.put("publicKey", publicKey);
			stringKeypair.put("privateKey", privateKey);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return stringKeypair;
	}

	// 암호화 PublicKey매개변수
	static String encode(String plainData, PublicKey publicKey) {
		String encryptedData = null;
		try {
			// 평문으로 전달받은 공개키를 공개키객체로 만드는 과정
			// PublicKey publicKey = getPublicKey(stringPublicKey);
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

	// 복호화 PrivateKey매개변수
	static String decode(String encryptedData, PrivateKey privateKey) {
		String decryptedData = null;
		try {
			// 평문으로 전달받은 개인키를 개인키객체로 만드는 과정
			// PrivateKey privateKey = getPrivateKey(stringPrivateKey);
			// 만들어진 개인키객체를 기반으로 암호화모드로 설정하는 과정
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			// 암호문을 평문화하는 과정
			byte[] byteEncryptedData = Base64.getDecoder().decode(encryptedData.getBytes());
			byte[] byteDecryptedData = cipher.doFinal(byteEncryptedData);
			decryptedData = new String(byteDecryptedData);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decryptedData;
	}

	// 암호화
	static String encode(String plainData, String stringPublicKey) {
		String encryptedData = null;
		try {
			// 평문으로 전달받은 공개키를 공개키객체로 만드는 과정
			PublicKey publicKey = getPublicKey(stringPublicKey);
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
	static String decode(String encryptedData, String stringPrivateKey) {
		String decryptedData = null;
		try {
			// 평문으로 전달받은 개인키를 개인키객체로 만드는 과정
			PrivateKey privateKey = getPrivateKey(stringPrivateKey);
			// 만들어진 개인키객체를 기반으로 암호화모드로 설정하는 과정
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			// 암호문을 평문화하는 과정
			byte[] byteEncryptedData = Base64.getDecoder().decode(encryptedData.getBytes());
			byte[] byteDecryptedData = cipher.doFinal(byteEncryptedData);
			decryptedData = new String(byteDecryptedData);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decryptedData;
	}

	static PublicKey getPublicKey(String stringPublicKey) {
		PublicKey publicKey = null;
		try {
			// 평문으로 전달받은 공개키를 공개키객체로 만드는 과정
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] bytePublicKey = Base64.getDecoder().decode(stringPublicKey.getBytes());
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
			// generatePublic : Generates a public key object from the provided key
			// specification (key material).
			publicKey = keyFactory.generatePublic(publicKeySpec);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return publicKey;
	}

	static PrivateKey getPrivateKey(String stringPrivateKey) {
		PrivateKey privateKey = null;
		try {
			// 평문으로 전달받은 개인키를 개인키객체로 만드는 과정
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] bytePrivateKey = Base64.getDecoder().decode(stringPrivateKey.getBytes());
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
			// generatePrivate : Generates a private key object from the provided key
			// specification (key material).
			privateKey = keyFactory.generatePrivate(privateKeySpec);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return privateKey;
	}

	// 서명생성 PrivateKey매개변수
	public static String sign(String plainText, PrivateKey privateKey) {
		try {
			// PrivateKey privateKey = getPrivateKey(strPrivateKey);
			// getInstance(String algorithm) : Returns a Signature object that implements
			// the specified signature algorithm.
			Signature privateSignature = Signature.getInstance("SHA256withRSA");
			// initSign(PrivateKey privateKey) : Initialize this object for signing.
			privateSignature.initSign(privateKey);
			// update(byte[] data) : Updates the data to be signed or verified, using the
			// specified array of bytes.
			privateSignature.update(plainText.getBytes("UTF-8"));
			// sign() : Returns the signature bytes of all the data updated.
			byte[] signature = privateSignature.sign();
			return Base64.getEncoder().encodeToString(signature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | UnsupportedEncodingException | SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	// 서명생성
	public static String sign(String plainText, String strPrivateKey) {
		try {
			PrivateKey privateKey = getPrivateKey(strPrivateKey);
			Signature privateSignature = Signature.getInstance("SHA256withRSA");
			privateSignature.initSign(privateKey);
			privateSignature.update(plainText.getBytes("UTF-8"));
			byte[] signature = privateSignature.sign();
			return Base64.getEncoder().encodeToString(signature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | UnsupportedEncodingException | SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	// 검증 PublicKey매개변수
	public static boolean verifySignarue(String plainText, String signature, PublicKey publicKey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature sig;
		System.out.println("plainText: " + plainText);
		System.out.println("signature: " + signature);
		System.out.println("publicKey: " + publicKey);
		/* try { */
		// PublicKey publicKey = getPublicKey(strPublicKey);
		sig = Signature.getInstance("SHA256withRSA");
		// initVerify(PublicKey publicKey) : Initializes this object for verification.
		sig.initVerify(publicKey);
		sig.update(plainText.getBytes());
		System.out.println("검증:" + sig.verify(Base64.getDecoder().decode(signature)));
		// verify(byte[] signature) : Verifies the passed-in signature.(리턴값 boolean)
		sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(publicKey);
		sig.update(plainText.getBytes());
		if (sig.verify(Base64.getDecoder().decode(signature))) {
			return true;
		} else {
			return false;
		}
		/*
		 * } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException
		 * e) { throw new RuntimeException(e); }
		 */
	}

	// 검증
	public static boolean verifySignarue(String plainText, String signature, String strPublicKey) {
		Signature sig;
		try {
			PublicKey publicKey = getPublicKey(strPublicKey);
			sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(publicKey);
			sig.update(plainText.getBytes());
			if (!sig.verify(Base64.getDecoder().decode(signature)));
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new RuntimeException(e);
		}
		return true;
	}
}