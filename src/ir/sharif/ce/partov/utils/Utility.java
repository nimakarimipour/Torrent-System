package ir.sharif.ce.partov.utils;

public class Utility {
	public static byte[] getBytes(long number) {
		return new byte[]{
				//Big endian output
				(byte) ((number >> 56) & 0xFFL),
				(byte) ((number >> 48) & 0xFFL),
				(byte) ((number >> 40) & 0xFFL),
				(byte) ((number >> 32) & 0xFFL),
				(byte) ((number >> 24) & 0xFFL),
				(byte) ((number >> 16) & 0xFFL),
				(byte) ((number >> 8) & 0xFFL),
				(byte) ((number) & 0xFFL)};
	}

	public static byte[] getBytes(int number) {
		return new byte[]{
				(byte) ((number >> 24) & 0xFF),
				(byte) ((number >> 16) & 0xFF),
				(byte) ((number >> 8) & 0xFF),
				(byte) ((number) & 0xFF)};
	}

	public static byte[] getBytes(short number) {
		return new byte[]{
				(byte) ((number >> 8) & 0xFF),
				(byte) ((number) & 0xFF)};
	}

	public static int convertBytesToInt(byte[] bytes) {
		return ((bytes[0] << 24) & 0xFF000000)
				+ ((bytes[1] << 16) & 0x00FF0000)
				+ ((bytes[2] << 8) & 0x0000FF00)
				+ ((bytes[3]) & 0x000000FF);
	}

	public static long convertBytesToLong(byte[] bytes) {
		return ((((long) bytes[0]) << 56) & 0xFF000000_00000000L)
				+ ((((long) bytes[1]) << 48) & 0x00FF0000_00000000L)
				+ ((((long) bytes[2]) << 40) & 0x0000FF00_00000000L)
				+ ((((long) bytes[3]) << 32) & 0x000000FF_00000000L)
				+ ((((long) bytes[4]) << 24) & 0x00000000_FF000000L)
				+ ((((long) bytes[5]) << 16) & 0x00000000_00FF0000L)
				+ ((((long) bytes[6]) << 8) & 0x00000000_0000FF00L)
				+ ((((long) bytes[7])) & 0x00000000_000000FFL);
	}

	public static short convertBytesToShort(byte[] bytes) {
		return (short) (((bytes[0] << 8) & 0xFF00) + (bytes[1] & 0x00FF));
	}

	public static String byteToHex(byte number) {
		int intNumber = number & 0xFF;
		return Utility.toHex((intNumber & 0xF0) >> 4) + ""
				+ Utility.toHex(intNumber & 0x0F);
	}

	public static char toHex(int decimalDigit) {
		return decimalDigit < 10 ? (char) (decimalDigit + '0')
				: (char) (decimalDigit - 10 + 'A');
	}

	public static String DectoHex(int dec) {
		String Hex = "";
		boolean sign = false;
		if (dec < 0) {
			sign = true;
			dec = -dec;
		}
		while (dec > 0) {
			Hex = toHex(dec & 0xF) + Hex;
			dec = dec >> 8;
		}
		return sign ? "-" + Hex : Hex;
	}

	public static String getIPString(byte[] ipBytes) {
		String ipStr = "";
		for (int i = 0; i < ipBytes.length; i++) {
			ipStr += ipBytes[i] & 0xFF; // inorder to convert to unsigned byte!
			if (i != ipBytes.length - 1) {
				ipStr += ".";
			}
		}
		return ipStr;
	}

	public static String getIPString(int ip) {
		return getIPString(getBytes(ip));
	}

	public static int Dec(String number) {
		int ans = 0;
		int sign = 1;
		if (number.contains("-"))
			sign = -1;
		for (int i = 0; i < number.length(); i++) {
			char c = number.charAt(i);
			if ('0' <= c && c <= '9')
				ans = ans * 10 + (c - '0');
		}
		return ans * sign;
	}

	public static int Hex(String number) {
		int ans = 0;
		int sign = 1;
		if (number.contains("-"))
			sign = -1;
		number = number.toLowerCase();
		for (int i = 0; i < number.length(); i++) {
			char c = number.charAt(i);
			if ('0' <= c && c <= '9')
				ans = ans * 16 + (c - '0');
			if ('a' <= c && c <= 'f')
				ans = ans * 16 + (c - 'a' + 10);
		}
		return ans * sign;
	}

	public static int getIP(String IPstring) {
		String part[] = IPstring.split("\\.");
		return (Dec(part[0]) << 24) +
				(Dec(part[1]) << 16) +
				(Dec(part[2]) << 8) +
				(Dec(part[3]));
	}

	public static byte[] getMac(String MacString) {
		byte[] mac = new byte[6];
		String part[] = MacString.split(":");
		for (int i = 0; i < 6; i++)
			mac[i] = (byte) Hex(part[i]);
		return mac;
	}

}
