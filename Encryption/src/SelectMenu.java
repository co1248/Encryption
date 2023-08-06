import java.util.Scanner;

/**
 * 
 * @author co1248
 * @Date : 2021-12-01
 */
public class SelectMenu {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		System.out.println("암호화 복호화 프로그램");
		int menu;
		String message;
		int key;
		Scanner scan = null;

		while (true) {
			scan = new Scanner(System.in);

			System.out.println("메뉴선택 : 1.암호화 2.복호화 (이외의 값 종료)");
			menu = scan.nextInt();
			if(menu != 1 && menu != 2) {
				System.out.println("종료합니다.");
				break;
			}

			System.out.println("메시지를 입력해주세요.");
			message = scan.next();

			System.out.println("key를 입력해주세요. (정수로 입력해주세요.)");
			key = scan.nextInt();

			if (menu == 1) {
				String plusMessage = ChangeAscii.encryption(message, key);
				System.out.println("입력된 메시지는 : " + message);
				System.out.println("암호화된 메시지는 : " + plusMessage);
			} else if (menu == 2) {
				String minusMessage = ChangeAscii.decryption(message, key);
				System.out.println("입력된 메시지는 : " + message);
				System.out.println("복호화된 메시지는 : " + minusMessage);
			}
		}
		scan.close();

		/*
		 * System.out.println(ChangeAscii.encryption("korea", 1));
		 * System.out.println(ChangeAscii.decryption("lpsfb", 1));
		 */
	}
}
