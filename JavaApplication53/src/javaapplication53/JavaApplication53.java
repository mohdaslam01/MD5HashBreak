/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package javaapplication53;
import java.io.*;
import java.security.*;
import java.math.BigInteger;
/**
 *
 * @author Aslam
 */
public class JavaApplication53 {

    /**
     * @param bytes
     * @return 
     */
    
    public static String toHex(byte []bytes){
        return String.format("%0"+(bytes.length<<1)+"X", new BigInteger(1, bytes));
    }
    public static void main(String[] args) {
        // TODO code application logic here
        
        try{
            FileInputStream shadowFile=new FileInputStream("C:/Users/Aslam/Downloads/P1_files/P1_files/shadow");
            for(int i=0; i<shadowFile.toString().length()-1; i++)
                System.out.println(shadowFile.toString().equals(" "));
            try (BufferedReader shadowReader = new BufferedReader(new InputStreamReader(shadowFile))) {
                String line;
                while((line=shadowReader.readLine())!=null){
                    String []parts=line.split(":");
                    if(parts.length<2){
                        System.out.println("not valid"+line);
                        continue;
                    }
                    String uname=parts[0];
                    String shash=parts[1];
                    FileInputStream commonPasswordsFile=new FileInputStream("C:/Users/Aslam/Downloads/P1_files/P1_files/common-passwords.txt");
                    String matchedPassword;
                    try (BufferedReader commonPR = new BufferedReader(new InputStreamReader(commonPasswordsFile))) {
                        String salt=extractSalt(shash);
                        matchedPassword = null;
                        while((line=commonPR.readLine())!=null){
                            String commonP=line;System.out.println(commonP);
                            String computedHash=MD5Shadow.crypt(commonP, salt);
                            if(computedHash.equals(computedHash)){
                                matchedPassword = commonP;
                                break;
                            }else{
                                System.out.println("Match not found\n\r"+line+""+computedHash);
                            }
                        }
                    }
                    if(matchedPassword!=null){
                        System.out.println(uname+":"+matchedPassword);
                    }
                }
            }
            
        }catch(IOException e){
            System.out.println(e);
        }
    }
    public static String extractSalt(String shash){
        String []fields=shash.split("\\$");
        if(fields.length<3) return "823";
        return "$"+fields[2]+"$";
    }
    
}

//class MD5Shadow {
//    public static String crypt(String input, String salt) {
//        try {
//            String inputWithSalt = input + salt;
//            MessageDigest md = MessageDigest.getInstance("MD5");
//            md.update(inputWithSalt.getBytes());
//            byte[] bytes = md.digest();
//            StringBuilder sb = new StringBuilder();
//            for (byte b : bytes) {
//                sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
//            }
//            return sb.toString();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//            return null; // Handle error
//        }
//    }
//}

class MD5Shadow
{

    /** magic is 1 for MD5 */
    private static final String magic = "$1$";
    
    /** Characters for base64 encoding */
    private static final String char64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private static byte[] Concat(byte[] array1, byte[] array2)
    {
        byte[] concat = new byte[array1.length + array2.length];
        for (int i = 0; i < concat.length; i++)
        {
            if (i < array1.length)
            {
                concat[i] = array1[i];
            }
            else
            {
                concat[i] = array2[i - array1.length];
            }
        }
        return concat;
    }

    private static byte[] PartialConcat(byte[] array1, byte[] array2, int max)
    {
        byte[] concat = new byte[array1.length + max];

        for (int i = 0; i < concat.length; i++)
        {
            if (i < array1.length)
            {
                concat[i] = array1[i];
            }
            else
            {
                concat[i] = array2[i - array1.length];
            }
        }
        return concat;
    }

    //This method would convert an value to the Base64 string
    private static String to64(int value, int length)
    {
        StringBuffer result;

        result = new StringBuffer();
        while (--length >= 0)
        {
            int ind = value & 0x3f;
            result.append(char64.substring(ind, ind + 1));
            value >>= 6;
        }
        return (result.toString());
    }
    
    public static String crypt(String password, String salt)
    {
        int saltEnd;
        int value;
        int i;

        byte[] pwBytes = null;
        byte[] saltBytes = null;
        byte[] ctx = null;
        byte[] ctx2 = null;

        StringBuilder result;
        MessageDigest hashGenerator = null;
        try
        {
            //initialize the MD5 hash generator
            hashGenerator = MessageDigest.getInstance("MD5");
        }
        catch (NoSuchAlgorithmException ex)
        {
            ex.printStackTrace();
        }

////////////////////////////////////////Some safety checks.... can be omitted..................
        // Skip magic if it exists with the salt..... checking for accidentally using along with magic
        if (salt.startsWith(magic))salt = salt.substring(magic.length());
        
        // Remove password hash if present..... checking for accidentally using along with pw
        if ((saltEnd = salt.lastIndexOf('$')) != -1)salt = salt.substring(0, saltEnd);
        
        // Shorten the salt to 8 characters if it is longer.......... assuming the salt must be 8 chars long
        if (salt.length() > 8)
        {
            salt = salt.substring(0, 8);
        }
///////////////////////////////////////////////////////////////////////////////////////////////

        ctx = (password + magic + salt).getBytes();
        ctx2 = hashGenerator.digest((password + salt + password).getBytes());


        /////////I am commenting out this one.... But for longer passwords, it should have to be enabled....
        
//        for (ind = password.length(); ind > 0; ind -= 16)
//        {
//            if (ind > 16)
//            {
//                ctx = Concat(ctx, ctx2);
//            }
//            else
//            {
//                ctx = PartialConcat(ctx, ctx2, ind);
//            }
//        }

        ctx = PartialConcat(ctx, ctx2, password.length());

        
        pwBytes = password.getBytes();

        //This is the equivalent of the while loop in the C code
        for (i = password.length(); i > 0; i >>= 1)
        {
            if ((i & 1) == 1)
            {
                ctx = Concat(ctx, new byte[]{0});
            }
            else
            {
                ctx = Concat(ctx, new byte[]{pwBytes[0]});
            }
        }

        ctx2 = hashGenerator.digest(ctx);

        byte[] ctx1;

        
        saltBytes = salt.getBytes();
        
        // Do some scramblings or mutations?!!
        for (i = 0; i < 1000; i++)
        {
            ctx1 = new byte[]
            {
            };
            if ((i & 1) == 1)
            {
                ctx1 = Concat(ctx1, pwBytes);
            }
            else
            {
                ctx1 = Concat(ctx1, ctx2);
            }
            if (i % 3 != 0)
            {
                ctx1 = Concat(ctx1, saltBytes);
            }
            if (i % 7 != 0)
            {
                ctx1 = Concat(ctx1, pwBytes);
            }
            if ((i & 1) != 0)
            {
                ctx1 = Concat(ctx1, ctx2);
            }
            else
            {
                ctx1 = Concat(ctx1, pwBytes);
            }
            ctx2 = hashGenerator.digest(ctx1);
        }
        result = new StringBuilder();

        // Do the shifting and add the Base64 converted hash to the result string
        value = ((ctx2[0] & 0xff) << 16) | ((ctx2[6] & 0xff) << 8) | (ctx2[12] & 0xff);
        result.append(to64(value, 4));
        value = ((ctx2[1] & 0xff) << 16) | ((ctx2[7] & 0xff) << 8) | (ctx2[13] & 0xff);
        result.append(to64(value, 4));
        value = ((ctx2[2] & 0xff) << 16) | ((ctx2[8] & 0xff) << 8) | (ctx2[14] & 0xff);
        result.append(to64(value, 4));
        value = ((ctx2[3] & 0xff) << 16) | ((ctx2[9] & 0xff) << 8) | (ctx2[15] & 0xff);
        result.append(to64(value, 4));
        value = ((ctx2[4] & 0xff) << 16) | ((ctx2[10] & 0xff) << 8) | (ctx2[5] & 0xff);
        result.append(to64(value, 4));
        value = ctx2[11] & 0xff;
        result.append(to64(value, 2));

//        return magic + salt + "$" + result.toString();
        return result.toString();
    }
    
}




