import java.util.Scanner;

/**
 * 
 * @author co1248
 * @Date : 2021-12-01
 */
public class AESTEST {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		System.out.println("대칭키(AES) 암호화 복호화 프로그램");
		AES256 aes256 = new AES256();
		int menu;
		String message;
		String key;
		Scanner scan = null;

		while (true) {
			scan = new Scanner(System.in);

			System.out.println("메뉴선택 : 1.암호화 2.복호화 (이외의 값 종료)");
			menu = scan.nextInt();
			if (menu != 1 && menu != 2) {
				System.out.println("종료합니다.");
				break;
			}
			scan.nextLine();

			System.out.println("메시지를 입력해주세요.");
			message = scan.nextLine();

			System.out.println("key를 입력해주세요.(16보다 길게, 한글제외)");
			key = scan.nextLine();

			if (menu == 1) {
				String cipherText = aes256.encrypt(message, key);
				System.out.println("입력된 메시지는 : " + message);
				System.out.println("암호화된 메시지는 : " + cipherText);
			} else if (menu == 2) {
				String decryptedMessage = aes256.decrypt(message, key);
				System.out.println("입력된 메시지는 : " + message);
				System.out.println("복호화된 메시지는 : " + decryptedMessage);
			}
		}
		scan.close();
	}
}
