package ir.sharif.ce.partov.base;

public abstract class Machine {
	private final ClientFramework clientFramework;
	private String customInfo;
	protected int countOfInterfaces;
	protected Interface[] iface;

	public Machine(ClientFramework clientFramework, int count) {
		this.clientFramework = clientFramework;
		this.countOfInterfaces = count;
		iface = new Interface[count];
	}

	public abstract void initialize();

	public abstract void run();

	public void initInterface(int index, long mac, int ip, int mask) {
		if (0 <= index && index < countOfInterfaces) {
			//NOTE: add index and cf
			//TODO: check client frame work
			iface[index] = new Interface(index, mac, ip, mask, clientFramework);
		}
	}

	public void printInterfacesInformation() {
		System.out.println("==========================================");
		for (int i = 0; i < countOfInterfaces; ++i) {
			if (i > 0) {
				System.out.println("---------------------");
			}
			System.out.println("Interface " + i + ":");
			iface[i].printInterfaceInformation();
		}
		System.out.println("==========================================");
	}

	public void setCustomInformation(String info) {
		this.customInfo = info;
	}

	public String getCustomInformation() {
		return customInfo;
	}

	public int getCountOfInterfaces() {
		return countOfInterfaces;
	}

	public synchronized boolean sendFrame(Frame frame, int ifaceIndex) {
		return clientFramework.sendFrame(frame, ifaceIndex);
	}

	public abstract void processFrame(Frame frame, int ifaceIndex);
}
