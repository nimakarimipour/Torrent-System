import ir.sharif.ce.partov.base.ClientFramework;
import ir.sharif.ce.partov.utils.Utility;

public class Main {
	private static boolean runCF(ClientFramework cf){
		return cf.connectToServer() && 	cf.doInitialNegotiations() && cf.startSimulation();
	}
	public static void main(String[] args) {
		ClientFramework cf = new ClientFramework(args);
		runCF(cf);
		ClientFramework.destroy();
	}

	static void printBytes(byte[] bytes){
		for (int i=0 ; i<bytes.length ; i++){
			System.out.println(Utility.byteToHex(bytes[i]));
			bytes[i]++;
		}
	}
}
