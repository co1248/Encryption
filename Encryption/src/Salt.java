import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * 
 * @author co1248
 * @Date : 2021-12-03
 */
public class Salt {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		Scanner sc = new Scanner(System.in);
		System.out.println("로그인 프로그램");

		System.out.println("비밀번호를 입력하세요.");
		String pw = sc.next();
		byte[] passw = pw .getBytes();
		sc.close();

		if (ch(passw)) {
			System.out.println("로그인 성공");
		} else {
			System.out.println("아이디 비번을 확인해주세요.");
		}

	}

	// 비밀번호 해싱
	private static String hasing(byte[] password, String Salt) throws Exception {

		MessageDigest md = MessageDigest.getInstance("SHA-256"); // SHA-256 해시함수를 사용

		// key-stretching
		for (int i = 0; i < 10000; i++) {
			String temp = Byte_to_String(password) + Salt; // 패스워드와 Salt 를 합쳐 새로운 문자열 생성
			md.update(temp.getBytes()); // temp 의 문자열을 해싱하여 md 에 저장해둔다
			password = md.digest(); // md 객체의 다이제스트를 얻어 password 를 갱신한다
		}

		return Byte_to_String(password);
	}

	// SALT 값 생성
	private static String getSalt() throws Exception {
		SecureRandom rnd = new SecureRandom();
		final int SALT_SIZE = 16;
		byte[] temp = new byte[SALT_SIZE];
		rnd.nextBytes(temp);

		return Byte_to_String(temp);
	}

	// 바이트 값을 16진수로 변경해준다
	private static String Byte_to_String(byte[] temp) {
		StringBuilder sb = new StringBuilder();
		for (byte a : temp) {
			sb.append(String.format("%02x", a));
		}
		return sb.toString();
	}
	//솔트값 생성하고 해싱한 뒤 인풋값과 저장된값을 체크
	public static boolean ch(byte[] inputwd) throws Exception {
		String salt = getSalt();
		String savepw = "abc";//저장된 패스워드
		byte[] password = savepw.getBytes();
		System.out.println("입력된 비밀번호 : " + hasing(inputwd, salt));
		System.out.println("저장된 비밀번호 : " + hasing(password, salt));
		if (hasing(inputwd, salt).equals(hasing(password, salt))) {
			return true;
		} else {
			return false;
		}
	}
}
