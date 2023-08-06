import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

/**
 * 
 * @author co1248
 * @Date : 2021-12-03
 */
public class Hash {
	public static void main(String[] args) throws NoSuchAlgorithmException {
		Scanner sc = new Scanner(System.in);
		System.out.println("로그인 프로그램");
		/*
		 * System.out.println("아이디를 입력하세요."); 
		 * String id = sc.next();
		 */
		System.out.println("비밀번호를 입력하세요.");
		String pw = sc.next();
		sc.close();
		String pword = hasing(pw);

		if (ch(pword)) {
			System.out.println("로그인 성공");
		} else {
			System.out.println("아이디 비번을 확인해주세요.");
		}

	}

	public static boolean ch(String pword) throws NoSuchAlgorithmException {
		String passwd = "abc";
		System.out.println("입력된 비밀번호 : " + pword);
		System.out.println("저장된 비밀번호 : " + hasing(passwd));
		if (pword.equals(hasing(passwd))) {
			return true;
		} else {
			return false;
		}
	}

	public static String hasing(String pw) throws NoSuchAlgorithmException {
		// MD5 or SHA-1 or SHA-256 원하는 해시 알고리즘을 넣는다.
		MessageDigest md = MessageDigest.getInstance("SHA-256"); // 해시 알고리즘에서 사용할 알고리즘의 종류를 적어준다.
		// 문자열 바이트로 메시지 다이제스트를 갱신
		md.update(pw.getBytes());
		return bytesToHex(md.digest());
	}

	// 바이트배열을 16진수 문자열로 변환하여 표시
	private static String bytesToHex(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		for (byte b : bytes) {
			builder.append(String.format("%02x", b));
		}
		return builder.toString();
	}
}
