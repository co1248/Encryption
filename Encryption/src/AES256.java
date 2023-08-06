import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author co1248
 * @Date : 2021-12-01
 */
public class AES256 {
	
	public String encrypt(String text, String key) throws Exception {
		// 패딩 : 데이터를 특정크기로 맞추기 위해서, 특정크기보다 부족한 부분의 공간을 의미없는 문자들로 채워서 비트수를 맞추는 것
		String alg = "AES/CBC/PKCS5Padding";
		//iv : 초기화 백터
		String iv = key.substring(0, 16); // 16byte 16보다 짧을 시 에러 발생 처리해야함. 1바이트 문자열이 아닐 때 나는 에러 처리해야함.
		//Cipher : 암호화는 권한이 있는 유저들만 메세지를 이해하거나 접근할 수 있도록 메세지를 인코딩하는 과정
		//Cipher 객체 인스턴스화하기
		Cipher cipher = Cipher.getInstance(alg);
		// SecretKeySpec : 지정된 바이트 배열에서 비밀키를 생성합니다.
		SecretKeySpec keySpec = new SecretKeySpec(iv.getBytes(), "AES");
		// IvParameterSpec : Creates an IvParameterSpec object using the bytes in iv as the IV.
		IvParameterSpec ivParamSpec = new IvParameterSpec(iv.getBytes());
		System.out.println("여기까진 되나?");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamSpec); //ENCRYPT_MODE: cipher 객체를 암호화 모드로 초기화한다. 
		//doFinal(byte[] input)Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
		byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
		return Base64.getEncoder().encodeToString(encrypted);
	}

	public String decrypt(String cipherText, String key) throws Exception {
		String alg = "AES/CBC/PKCS5Padding";
		String iv = key.substring(0, 16); // 16byte
		Cipher cipher = Cipher.getInstance(alg);
		SecretKeySpec keySpec = new SecretKeySpec(iv.getBytes(), "AES");
		IvParameterSpec ivParamSpec = new IvParameterSpec(iv.getBytes());
		//init(int opmode, Key key, AlgorithmParameters params) : Initializes this cipher with a key and a set of algorithm parameters.
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec); // DECRYPT_MODE: cipher 객체를 복호화 모드로 초기화한다. 

		byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
		byte[] decrypted = cipher.doFinal(decodedBytes);
		return new String(decrypted, "UTF-8");
	}
}
