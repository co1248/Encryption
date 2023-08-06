/**
 * 
 * @author co1248
 * @Date : 2021-12-01
 */
public class ChangeAscii {
	static char[] charMessage; //2메소드에서 쓰일거라 static으로

	public static String encryption(String message, int key) {
		charMessage = message.toCharArray();//String -> Char배열로
		for (int i = 0; i < message.length(); i++) {
			charMessage[i] += key;
		}
		return String.valueOf(charMessage);//Char배열 -> String으로
	}

	public static String decryption(String message, int key) {
		charMessage = message.toCharArray();
		for (int i = 0; i < message.length(); i++) {
			charMessage[i] -= key;
		}
		return String.valueOf(charMessage);
	}
}
