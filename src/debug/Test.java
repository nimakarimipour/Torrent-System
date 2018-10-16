package debug;

import java.util.Random;
import java.util.Scanner;

/**
 *  Created by nima on 12/10/16.
 */

public class Test {

    public static void main(String[] args) throws Exception {

        Scanner s = new Scanner(System.in);
        int wait = s.nextInt();

        Machine m = new Machine();

        for (int i = 0; i < 100000; i++) {
            System.out.println(m.getTexts());
            Thread.sleep(wait);
        }
    }
}

class Machine{

    private String[] chars = {"q", "w", "e", " ", "r", "t", "y", "u",
            "i", "o", "p", "a", "s", " ", "d", "f", "g",
            "h", "j", "k", " ", "l", "z", "x", " ", "c", "v", "b",
            "n", " ", "m", "43", " 12.123.12 ", " 43.123.242 ", " ",  " 534.121.321 "
    , " & ", " " , " (ksa) ", " @ ", " : ", " -> ", " ", " -> ", " + ", " = ", "53252", "314", " "};

    private Random randomLength = new Random(System.currentTimeMillis());
    private Random r = new Random(System.currentTimeMillis());
    private int l;

    Machine() {
        l = chars.length;
    }

    String getTexts(){
        int length = randomLength.nextInt(30) + 15;
        String ans = "";
        for (int i = 0; i < length; i++) ans += chars[r.nextInt(l)];
        return ans;
    }
}