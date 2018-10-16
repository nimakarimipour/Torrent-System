package debug.print;

/**
 *  Created by nima on 12/10/16.
 */
public class SimplePrinter {

    public static void print(String s){
        //System.out.println("* " + s);
    }

    public static void print(byte[] bytes, String message){
        print(message);
        print("The contents:");
        for(byte b : bytes){
            System.out.print(b + " ");
        }
        print("end\n");
    }
}