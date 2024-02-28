// TEAM:
// vp569 - vutham prerepa
// tk369 - Tanmai Kalahasti
// vn272 - N.V. Jaya pavan





import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.math.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class FileRead {

  public static String toHex(byte[] bytes) {
    BigInteger bi = new BigInteger(1, bytes);
    return String.format("%0" + (bytes.length << 1) + "X", bi);
  }

  public static void hash_password(String[] user_details) {
    try {

      List<String> lines = Files.readAllLines(Paths.get("common-passwords.txt"));
      MessageDigest md = MessageDigest.getInstance("MD5");

      lines.forEach(
          (temp) -> {
            String passToTest = user_details[1] + temp;
            md.update(passToTest.getBytes());
            byte[] digest = md.digest();
            passToTest = toHex(digest);
            if (passToTest.equals(user_details[2])) {
              System.out.println(user_details[0] + " : " + temp);
            }
          });

    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }

  }

  public static void main(String args[]) {
    try {
      List<String> uids = Files.readAllLines(Paths.get("shadow-simple"));
      uids.forEach(
          (temp) -> {
            hash_password(temp.split(":"));
            ;
          });
    } catch (IOException e) {
      e.printStackTrace();
    }

  }
}
