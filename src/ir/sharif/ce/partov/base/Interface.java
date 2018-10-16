//FULLY UPDATED!


package ir.sharif.ce.partov.base;

import static ir.sharif.ce.partov.utils.Utility.getBytes;
import static ir.sharif.ce.partov.utils.Utility.byteToHex;


public class Interface {
	public final static int MAC_ADDRESS_LENGTH = 6;

	public byte[] mac;
	public int ip;
	public int mask;
	public int index;
	private ClientFramework cf;

	//NOTE: add index and cf
	public Interface(int index, long mac, int ip, int mask, ClientFramework cf) {
		this.cf = cf;
		this.index = index;
		this.mac = new byte[MAC_ADDRESS_LENGTH];
		System.arraycopy(getBytes(mac), 0, this.mac, 0,
				MAC_ADDRESS_LENGTH);
		this.ip = ip;
		this.mask = mask;
	}
	
	public void printInterfaceInformation() {
		System.out.println("-- Type: Ethernet interface");
		String macStr = "";
		for (int i = 0; i < MAC_ADDRESS_LENGTH; i++) {
			macStr += byteToHex(mac[i]);
			if (i != MAC_ADDRESS_LENGTH - 1) {
				macStr += ":";
			}
		}
		System.out.println("-- MAC address: " + macStr);
		byte[] ipBytes = getBytes(ip);
		String ipStr = "";
		for (int i = 0; i < ipBytes.length; i++) {
			ipStr += ipBytes[i] & 0xFF; // inorder to convert to unsigned byte!
			if (i != ipBytes.length - 1) {
				ipStr += ".";
			}
		}
		System.out.println("-- IP address: " + ipStr);
		byte[] maskBytes = getBytes(mask);
		String maskStr = "";
		for (int i = 0; i < maskBytes.length; i++) {
			maskStr += maskBytes[i] & 0xFF;
			if (i != maskBytes.length - 1) {
				maskStr += ".";
			}
		}
		System.out.println("-- Network mask: " + maskStr);
	}
	
	//NOTE: add get ip
	public int getIp(){
		return ip;
	}
	//NOTE: add set IP		
	public boolean setIp(int ip){
		if(ip != this.ip){
			if(cf.notifyChangeOfIPAddress(ip, index)){
				this.ip=ip;
				return true;
			}
		}
		return false;
	}
	
	//NOTE: add getMask
	public int getMask(){
		return mask;
	}
	
	//NOTE: add setMask
	public boolean setMask(int mask){
		if(mask != this.mask){
			if(cf.notifyChangeOfNetmask(mask, index)){
				this.mask=mask;
				return true;
			}
		}
		return false;
	}
}
