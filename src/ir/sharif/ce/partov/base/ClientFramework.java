package ir.sharif.ce.partov.base;

import ir.sharif.ce.partov.user.SimulateMachine;
import ir.sharif.ce.partov.utils.Utility;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class ClientFramework {
	//NOTE: MOVE THIS TWO CONSTANT
	public final static int FRAME_BUFFER_SIZE = 1524;

	protected enum StubCommunicationProtocolType {
		SigningInNegotiationType, MapNodeSelectingNegotiationType, InformationSynchronizationType, SimulationStartedNotificationType, RawFrameReceivedNotificationType, InvalidInterfaceIndexType
	}

	//NOTE: add NONE
	protected enum InformationSynchronizationSubTypes {
		NONE, InterfacesInformationSynchronizationSubType, CustomInformationSynchronizationSubType
	}

	protected enum MapNodeSelectingNegotiationCommands {
		MapNotExistCommand, DuplicateMapIdCommand, MapSelectedCommand, NodeNotExistCommand, NodeSelectedCommand, OutOfResourceCommand, MapInstanceResourcesAreReleased
	}

	protected enum InformationRequestingCommand {
		InterfacesInformationRequestCommand, CustomInformationRequestCommand, StartingSimulationRequestCommand
	}

	//NOTE: Add three last enum
	protected enum SimulationCommand {
		DisconnectCommand, SendFrameCommand, ChangeIPAddressCommand, ChangeNetmaskCommand, WalkOnFiniteStateMachineCommand
	}

	private boolean connected;
	//private String progName;
	private int ip;
	private short port;

	private InetAddress server;

	private String mapName;
	private String nodeName;

	private String userName;
	private String password;

	private String creatorId;
	private int needNewMap;

	private Machine machine;

	private static long sentBytes;
	private static long receivedBytes;

	
	//NOTE: me in C++ API
	private static ClientFramework instance;

	public static Object mutexObject;
	public static Object initializationCompletedCondition;
	private static boolean initialized;

	protected Socket sfd;
	protected byte[] buffer = new byte[FRAME_BUFFER_SIZE];

//NOTE: changed to public from private	
	public ClientFramework(String[] args) {
		connected = false;
		machine = null;
		//NOTE: add prgName
		//progName = args[0];
		parseArguments(args);

		
		//TODO: it seems same... [51]
		initialized = false;
		mutexObject = new Object();
		initializationCompletedCondition = new Object();
	}
	
	//TODO: destructor!

	protected boolean sendOrReceive(boolean sendIt, int errorCode, int size) {
		if(buffer.length<size)
			buffer = new byte[FRAME_BUFFER_SIZE];
		return sendOrReceive(sendIt, errorCode, size, buffer);
	}

	protected boolean sendOrReceive(boolean sendIt, int errorCode, int size,
			byte[] buf) {
		try {
			if (sendIt) {
				sfd.getOutputStream().write(buf, 0, size);
			} else {
				if (sfd.getInputStream().read(buf, 0, size) == -1) {
					throw new IOException();
				}
			}
		} catch (IOException e) {
			if (errorCode == -1) {
				return false;
			}
			System.out.println("[Failed]");
			System.out.println("+++ Initial negotiations failed. [error code "
					+ errorCode + "]");
			return false;
		}
		return true;
	}

	public static void init(String[] args) {
		if (instance != null) {
			return;
		}
		instance = new ClientFramework(args);
	}

	public static ClientFramework getInstance() {
		return instance;
	}

	@Override
	protected void finalize() throws Throwable {
		if (connected) {
			sfd.close();
		}
		super.finalize();
	}

	public static void destroy() {
		try {
			if(instance != null)
				instance.finalize();
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	public static void systemInterrupt() {
		System.out.println();
		System.out.println("==========================================");
		System.out.println("Sent: " + sentBytes + " bytes(s)");
		System.out.println("Received: " + receivedBytes + " bytes(s)");

		destroy();
		// FIXME
	}
//TODO: IT SEEMS SAME
	public boolean connectToServer() {
		byte[] ipBytes = server.getAddress();
		String ipStr = Utility.getIPString(ipBytes);
		System.out.println("Connecting to Partov server at " + ipStr + ":"
				+ (port & 0xFFFF));
		System.out.print("           to map/node \"" + mapName + "\"/\""
				+ nodeName + "\" ... ");
		System.out.flush();
		connected = true;
		try {
			sfd = new Socket(server, port & 0xFFFF);
		} catch (IOException e) {
			System.out.println("[Failed]");
			return false;
		}
		System.out.println("[Done]");
		return true;
	}

	public boolean doInitialNegotiations() {
		return doSigningInNegotiations(buffer)
				&& doMapSelectingNegotiations(buffer)
				&& doNodeSelectingNegotiations(buffer)
				&& doInformationSynchronizationNegotiations(buffer);
	}
	
//NOTE: added this function
	public boolean doInitialRecoveryNegotiations() {
		return doSigningInNegotiations(buffer)
				&& doMapSelectingNegotiations(buffer)
				&& doNodeSelectingNegotiations(buffer);
	}

	public boolean startSimulation() {
		System.out.println("Starting simulation... ");
		buffer = Utility
				.getBytes(InformationRequestingCommand.StartingSimulationRequestCommand
						.ordinal());
		
		if (!sendOrReceive(true, 24, 4/*Size of uint32*/)) {
			return false;
		}
		if (!sendOrReceive(false, 25, 4/*Size of uint32*/)) {
			return false;
		}
		
		int c = Utility.convertBytesToInt(buffer);
		if (c != StubCommunicationProtocolType.SimulationStartedNotificationType
				.ordinal()) {
			System.out.println("[Failed]");
			System.out
					.println("+++ Starting simulation does not verified by server.");
		}
		
		//TODO: THIS IS NOT IN C++ API
		Thread thread = new Thread(){
			@Override
			public void run() {
				systemInterrupt();
			}
		};
		Runtime.getRuntime().addShutdownHook(thread);
		// TODO SIGACTION???!!

		System.out.println("[Done]");
		System.out
				.println("Simulation started. You will receive all frames of the machine from now on.");
		System.out.println("==========================================");

		simulateMachine();
		systemInterrupt();
		
		return true;
	}

	public void simulateMachine() {
		new Thread() {
			@Override
			public void run() {
				st_run(machine);
			}
		}.start();
		synchronized (mutexObject) {
			while (!initialized) {
				try {
					//NOTE: add synchornized block
					synchronized(initializationCompletedCondition){
						initializationCompletedCondition.wait();
					}
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
		
		simulationEventLoop ();
		//TODO:۷۷۷۷
		//recoverSimulation ();
	}	
	private void simulationEventLoop(){	
		while (true) {
			if (!sendOrReceive(false, -1, 4 + 2)) {
				System.out
						.println("An IO exception occurred (error code 26). Aborting simulation...");
				break;
			}
			byte[] buf = new byte[4];
			System.arraycopy(buffer, 0, buf, 0, 4);
			int c = Utility.convertBytesToInt(buf);
			buf = new byte[2];
			System.arraycopy(buffer, 4, buf, 0, 2);
			int size = Utility.convertBytesToShort(buf) & 0xFFFF;
			if (c == StubCommunicationProtocolType.InvalidInterfaceIndexType
					.ordinal()) {
				if (size < 1 || !sendOrReceive(false, -1, size)) {
					System.out
							.println("An IO exception occurred (error code 27). Aborting simulation...");
					break;
				}
				String desc = new String(buffer);
				System.out
						.println("Error in sending frame on simulated machine (interface index was wrong).");
				System.out.println("-- " + desc);
				continue;
			}
			if (c != StubCommunicationProtocolType.RawFrameReceivedNotificationType
					.ordinal()
					|| size < 4 || size > FRAME_BUFFER_SIZE) {
				System.out
						.println("An IO exception occurred (error code 28). Aborting simulation...");
				break;
			}
			if (!sendOrReceive(false, -1, size)) {
				System.out
						.println("An IO exception occurred (error code 29). Aborting simulation...");
				break;
			}
			int interfaceIndex = Utility.convertBytesToInt(buffer);
			if (interfaceIndex < 0
					|| interfaceIndex >= machine.getCountOfInterfaces()) {
				System.out
						.println("An IO exception occurred (error code 30). Aborting simulation...");
				break;
			}
			size -= 4;
			buf = new byte[size];
			System.arraycopy(buffer, 4, buf, 0, size);
			receivedBytes += size;
			machine.processFrame(new Frame(size, buf), interfaceIndex);
		}
	}

	public void printArguments() {
		System.out.println("==========================================");
		System.out.println("Server ip: "
				+ Utility.getIPString(Utility.getBytes(ip)));
		System.out.println("Server port: " + (port & 0xFFFF));
		System.out.println("Map name: " + mapName);
		if (nodeName.length() == 0) {
			System.out.println("Node name not specified.");
		} else {
			System.out.println("Node name: " + nodeName);
		}
		System.out.println("==========================================");
	}

	public boolean sendFrame(Frame frame, int ifaceIndex) {
		boolean result = false;
		synchronized (mutexObject) {
			result = realSendFrame(frame, ifaceIndex);
		}
		return result;
	}

	protected boolean realSendFrame(Frame frame, int ifaceIndex) {
		byte[] mybuf = new byte[2 * 4 + 2];
		if (frame.length < 14 || frame.length >= ((1 << 16) - 4)) {
			System.err.println("UN accepatable Frame length:"+frame.length);
			System.out
					.println("Error in sending frame on simulated machine. [error code 31]");
			return false;
		}
		System.arraycopy(Utility.getBytes(SimulationCommand.SendFrameCommand
				.ordinal()), 0, mybuf, 0, 4);
		System.arraycopy(Utility.getBytes((short) (4 + frame.length)), 0,
				mybuf, 4, 2);
		System.arraycopy(Utility.getBytes(ifaceIndex), 0, mybuf, 6, 4);

		if (!sendOrReceive(true, -1, 2 * 4 + 2, mybuf)) {
			System.out
					.println("Error in sending frame on simulated machine. [error code 32]");
			return false;
		}
		if (!sendOrReceive(true, -1, frame.length, frame.data)) {
			System.out
					.println("Error in sending frame on simulated machine. [error code 33]");
			return false;
		}
		sentBytes += frame.length;
		return true;
	}

	private void parseArguments(String[] args) {
		final int MAX_COUNT_OF_ARGS = 8;
		final int COUNT_OF_OPTIONAL_ARGS = 2;
		boolean[] mark = new boolean[MAX_COUNT_OF_ARGS];
		for (int i = 0; i < args.length; ++i) {
			if (args[i].equals("--ip")) {
				checkForRedundantArgument(mark, 0);
				parseIPArgument(args[++i]);
			} else if (args[i].equals("--port")) {
				checkForRedundantArgument(mark, 1);
				parsePortArgument(args[++i]);
			} else if (args[i].equals("--map")) {
				checkForRedundantArgument(mark, 2);
				parseMapNameArgument(args[++i]);
			} else if (args[i].equals("--user")) {
				checkForRedundantArgument(mark, 3);
				parseUserNameArgument(args[++i]);
			} else if (args[i].equals("--pass")) {
				checkForRedundantArgument(mark, 4);
				parsePasswordArgument(args[++i]);
			} else if (args[i].equals("--id")) {
				checkForRedundantArgument(mark, 5);
				parseIDArgument(args[++i]);
				needNewMap = 0;
			} else if (args[i].equals("--new")) {
				checkForRedundantArgument(mark, 5);
				needNewMap = 1;
			} else if (args[i].equals("--free")) {
				checkForRedundantArgument(mark, 5);
				needNewMap = -1;
			} else if (args[i].equals("--node")) {
				checkForRedundantArgument(mark, 6);
				parseNodeNameArgument(args[++i]);
			}//NOTE: add this new 'if'
			else if (args[i].equals("--args")) {
				checkForRedundantArgument(mark, 7);
				int userProgramArgc = args.length - ++i;
				//TODO: in c++ it send by it refrence!
				parseUserProgramArguments (userProgramArgc , args[i]);	
			} else {
				usage();
			}
		}
		final int COUNT_OF_MANDATORY_ARGS = MAX_COUNT_OF_ARGS
				- COUNT_OF_OPTIONAL_ARGS;
		for (int i = 0; i < COUNT_OF_MANDATORY_ARGS; ++i) {
			if (!mark[i]) {
				usage();
			}
		}
		//TODO: is it the same in [126]!?
		try {
			server = InetAddress.getByAddress(Utility.getBytes(ip));
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
	}

	private void parseIPArgument(String arg) {
		try {
			ip = parseIP(arg);
		} catch (RuntimeException e) {
			usage();
		}
	}

	private void parsePortArgument(String arg) {
		try {
			port = parsePort(arg);
		} catch (RuntimeException e) {
			usage();
		}
	}

	private void parseMapNameArgument(String arg) {
		mapName = arg;
	}

	private void parseUserNameArgument(String arg) {
		userName = arg;
	}

	private void parseIDArgument(String arg) {
		creatorId = arg;
	}

	private void parsePasswordArgument(String arg) {
		password = arg;
	}

	private void parseNodeNameArgument(String arg) {
		nodeName = arg;
	}

	private void checkForRedundantArgument(boolean[] marks, int index) {
		if (marks[index]) {
			usage();
		}
		marks[index] = true;
	}

	private void parseUserProgramArguments(int argc, String arg){
		//TODO:No Need Today!
	}
	
	private int parseIP(String ipString) {
		ipString += ".";
		int dotPos = 0;
		byte[] bytes = new byte[4];
		for (int i = 0; i < 4; i++) {
			int ndp = ipString.indexOf(".", dotPos);
			if (ndp == -1) {
				throw new RuntimeException("Bad IP String!");
			}
			int num = 0;
			if (ndp - dotPos > 3) {
				throw new RuntimeException("Bad IP String!");
			}
			while (dotPos < ndp) {
				int d = ipString.charAt(dotPos++) - '0';
				if (d < 0 || d > 9) {
					throw new RuntimeException("Bad IP String!");
				}
				num = num * 10 + d;
			}
			if (num > 255) {
				throw new RuntimeException("Bad IP String!");
			}
			bytes[i] = (byte) num;
			++dotPos;
		}
		if (dotPos != ipString.length())
			throw new RuntimeException("Bad IP String!");
		return Utility.convertBytesToInt(bytes);
	}

	private short parsePort(String port) {
		int num = 0;
		for (int i = 0; i < port.length(); ++i) {
			int digit = port.charAt(i) - '0';
			if (digit < 0 || digit > 9) {
				throw new RuntimeException("Bad Port String!");
			}
			num = num * 10 + digit;
		}
		if (num >= (1 << 16)) {
			throw new RuntimeException("Bad Port String!");
		}
		return (short) num;
	}

	protected boolean doSigningInNegotiations(byte[] buf) {
		System.out.print("Signing in... ");
		System.out.flush();
		if (userName.length() > 20 || password.length() > 50) {
			System.out.println("[Failed]");
			System.out.println("+++ Username/Password is too long!!");
			return false;
		}
//		short ts = Utility.convertBytesToShort(buf);

		int offset = 2;
		short size = (short) (userName.length() + 1);
		System.arraycopy(Utility.getBytes(size), 0, buf, offset, 2);
		offset += 2;
		System.arraycopy(userName.getBytes(), 0, buf, offset, size - 1);
		buf[offset + size - 1] = 0;
		offset += size;

		size = (short) (password.length() + 1);
		System.arraycopy(Utility.getBytes(size), 0, buf, offset, 2);
		offset += 2;
		System.arraycopy(password.getBytes(), 0, buf, offset, size - 1);
		buf[offset + size - 1] = 0;
		offset += size;

		//NOTE: Move '-2'
		size = (short) (offset-2);
		System.arraycopy(Utility.getBytes(size), 0, buf, 0, 2);

		if (!sendOrReceive(true, 40, offset)) {
			return false;
		}
		if (!sendOrReceive(false, 41, 2 * 4)) {
			return false;
		}
		byte[] bytes = new byte[4];
		offset = 0;
		System.arraycopy(buffer, offset, bytes, 0, 4);
		int c1 = Utility.convertBytesToInt(bytes);
		offset += 4;
		System.arraycopy(buffer, offset, bytes, 0, 4);
		int c2 = Utility.convertBytesToInt(bytes);
		offset += 4;
		if (c1 != StubCommunicationProtocolType.SigningInNegotiationType
				.ordinal()
				|| c2 != 1) {
			System.out.println("[Failed]");
			System.out
					.println("+++ Username or password is incorrect. [error code 42]");
			return false;
		} else {
			System.out.println("[Done]");
		}
		//System.err.println("<<<1:"+size);
		return true;
	}

	protected boolean doMapSelectingNegotiations(byte[] buf) {
		System.out.print("Selecting map... ");
		System.out.flush();

		if (needNewMap != 0) {
			creatorId = userName;
		}
		if (3 * 2 + mapName.length() + creatorId.length() + 4 > FRAME_BUFFER_SIZE) {
			System.out.println("[Failed]");
			System.out.println("+++ Map name is too long.");
			return false;
		}

		int offset = 2;
		short size = (short) (mapName.length() + 1);
		System.arraycopy(Utility.getBytes(size), 0, buf, offset, 2);
		offset += 2;
		System.arraycopy(mapName.getBytes(), 0, buf, offset, size - 1);
		buf[offset + size - 1] = 0;
		offset += size;

		size = (short) (creatorId.length() + 1);
		System.arraycopy(Utility.getBytes(size), 0, buf, offset, 2);
		offset += 2;
		System.arraycopy(creatorId.getBytes(), 0, buf, offset, size - 1);
		buf[offset + size - 1] = 0;
		offset += size;

		System.arraycopy(Utility.getBytes(needNewMap), 0, buf, offset, 4);
		offset += 4;

		size = (short) (offset - 2);
		System.arraycopy(Utility.getBytes(size), 0, buf, 0, 2);

		if (!sendOrReceive(true, 2, offset)) {
			return false;
		}
		do {
			if (!sendOrReceive(false, 3, 2 * 4)) {
				return false;
			}
			byte[] bytes = new byte[4];
			offset = 0;
			System.arraycopy(buffer, offset, bytes, 0, 4);
			int c1 = Utility.convertBytesToInt(bytes);
			offset += 4;
			System.arraycopy(buffer, offset, bytes, 0, 4);
			int c2 = Utility.convertBytesToInt(bytes);
			offset += 4;
			if (c1 != StubCommunicationProtocolType.MapNodeSelectingNegotiationType
					.ordinal()) {
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed. [error code 4]");
				return false;
			}
			switch (MapNodeSelectingNegotiationCommands.values()[c2]) {
			case MapNotExistCommand:
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed (map not exists). [error code 5]");
				return false;

			case DuplicateMapIdCommand:
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed (duplicate map id). [error code 6]");
				return false;

			case MapSelectedCommand:
				System.out.println("[Done]");
				break;

			case MapInstanceResourcesAreReleased:
				System.out.println("[Done]");
				System.out
						.println("+++ Whole of the resources of the map instance are released.");
				return false;

			case OutOfResourceCommand:
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed (out of resource; retry later). [error code 7]");
				return false;

			default:
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed. [error code 8]");
				return false;
			}
		} while (false);
		return true;
	}

	protected boolean doNodeSelectingNegotiations(byte[] buf) {
		if (nodeName == null || nodeName.length() == 0) {
			// there is no node name specified.
			// so we should just wait forever in order to let map work itself.
		    
			System.out
					.println("No node name specified. So we could exit now.");
			System.out.println("The map will remain on the server. Do not forget to free it after simulation.");
			destroy ();
			return false;	
		}
		System.out.print("Connecting to node... ");
		System.out.flush();

		int offset = 0;
		int ms = nodeName.length() + 1;
		System.arraycopy(Utility.getBytes((short) ms), 0, buf, offset, 2);
		offset += 2;

		if (ms > FRAME_BUFFER_SIZE - 2) {
			System.out.println("[Failed]");
			System.out.println("+++ Node name is too long.");
			return false;
		}
		System.arraycopy(nodeName.getBytes(), 0, buf, offset, ms - 1);
		buf[offset + ms - 1] = 0;
		offset += ms;

		if (!sendOrReceive(true, 9, offset)) {
			return false;
		}
		// processing server response...
		do {
			if (!sendOrReceive(false, 10, 2 * 4)) {
				return false;
			}
			byte[] bytes = new byte[4];
			offset = 0;
			System.arraycopy(buffer, offset, bytes, 0, 4);
			int c1 = Utility.convertBytesToInt(bytes);
			offset += 4;
			System.arraycopy(buffer, offset, bytes, 0, 4);
			int c2 = Utility.convertBytesToInt(bytes);
			offset += 4;
			if (c1 != StubCommunicationProtocolType.MapNodeSelectingNegotiationType
					.ordinal()) {
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed. [error code 11]");
				return false;
			}
			switch (MapNodeSelectingNegotiationCommands.values()[c2]) {
			case NodeNotExistCommand:
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed (node not exists). [error code 12]");
				return false;

			case NodeSelectedCommand:
				System.out.println("[Done]");
				break;

			default:
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed. [error code 13]");
				return false;
			}
		} while (false);

		return true;
	}

	protected boolean doInformationSynchronizationNegotiations(byte[] buf) {
		System.out.println("Synchronizing information... ");

		if (!doInterfacesInformationSynchronizationNegotiations(buf)) {
			return false;
		}
		if (!doCustomInformationSynchronizationNegotiations(buf)) {
			return false;
		}
		System.out.println("[Done]");

		machine.printInterfacesInformation();
		String ci = machine.getCustomInformation();
		if (ci.length() == 0) {
			System.out
					.println("There is no custom information for this machine.");
		} else {
			System.out.println("Custom information for this machine are:");
			System.out.println(ci);
		}
		System.out.println("==========================================");
		return true;
	}

	protected boolean doInterfacesInformationSynchronizationNegotiations(
			byte[] buf) {
		int index = InformationRequestingCommand.InterfacesInformationRequestCommand
				.ordinal();
		
		System.arraycopy(Utility.getBytes(index), 0, buf, 0, 4);
		if (!sendOrReceive(true, 14, 4)) {
			return false;
		}
		do {
			if (!sendOrReceive(false, 15, 3 * 4)) {
				return false;
			}
			byte[] bytes = new byte[4];
			int offset = 0;
			System.arraycopy(buffer, offset, bytes, 0, 4);
			int c1 = Utility.convertBytesToInt(bytes);
			offset += 4;
			System.arraycopy(buffer, offset, bytes, 0, 4);
			int c2 = Utility.convertBytesToInt(bytes);
			offset += 4;
			System.arraycopy(buffer, offset, bytes, 0, 4);
			int count = Utility.convertBytesToInt(bytes);
			offset += 4;
			
			if (c1 != StubCommunicationProtocolType.InformationSynchronizationType
					.ordinal()
			//NOTE +1 added(deleted)
					|| c2 != InformationSynchronizationSubTypes.InterfacesInformationSynchronizationSubType
							.ordinal() || count < 1) {
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed. [error code 16]");
				return false;
			}
			
			machine = new SimulateMachine(this, count);
			for (int i = 0; i < count; i++) {
				if (!readInterfaceInformation(buffer, i)) {
					return false;
				}
			}
		} while (false);

		return true;
	}

	protected boolean readInterfaceInformation(byte[] buf, int index) {
		if (!sendOrReceive(false, 17, 2)) {
			return false;
		}
		int size = Utility.convertBytesToShort(buf) & 0xFFFF;
		if (size > FRAME_BUFFER_SIZE) {
			System.out.println("[Failed]");
			System.out
					.println("+++ Initial negotiations failed. [error code 18]");
			return false;
		}
		if (!sendOrReceive(false, 19, size)) {
			return false;
		}
		String ifName = new String(buf);
		ifName = ifName.substring(0,ifName.indexOf((char)0x00));
		
		if (!ifName.equals("edu::sharif::partov::nse::map::interface::EthernetInterface")
				&& !ifName
						.equals("edu::sharif::partov::nse::map::interface::EthernetPhysicalInterface")) {
			System.out.println("[Failed]");
			System.out
					.println("+++ Initial negotiations failed (unknown interface type). [error code 19]");
			return false;
		}
		int offset = size - 8 - 2 * 4;

		byte[] bytes = new byte[8];
		System.arraycopy(buf, offset, bytes, 0, 8);
		long mac = Utility.convertBytesToLong(bytes);
				
		offset += 8;

		bytes = new byte[4];
		System.arraycopy(buf, offset, bytes, 0, 4);
		int ip = Utility.convertBytesToInt(bytes);
		offset += 4;

		bytes = new byte[4];
		System.arraycopy(buf, offset, bytes, 0, 4);
		int mask = Utility.convertBytesToInt(bytes);
		offset += 4;

		machine.initInterface(index, mac, ip, mask);

		return true;
	}

	protected boolean doCustomInformationSynchronizationNegotiations(byte[] buf) {
		int index = InformationRequestingCommand.CustomInformationRequestCommand
				.ordinal();
		System.arraycopy(Utility.getBytes(index), 0, buf, 0, 4);
		if (!sendOrReceive(true, 20, 4)) {
			return false;
		}
		// synchronizing custom information...
		do {
			if (!sendOrReceive(false, 21,	 2 * 4 + 2)) {
				return false;
			}
			byte[] bytes = new byte[4];
			int offset = 0;
			System.arraycopy(buffer, offset, bytes, 0, 4);
			int c1 = Utility.convertBytesToInt(bytes);
			offset += 4;
			System.arraycopy(buffer, offset, bytes, 0, 4);
			int c2 = Utility.convertBytesToInt(bytes);
			offset += 4;
			System.arraycopy(buffer, offset, bytes, 0, 2);
			int size = Utility.convertBytesToShort(bytes) & 0xFFFF;
			offset += 2;

			if (c1 != StubCommunicationProtocolType.InformationSynchronizationType.ordinal()
					|| c2 != InformationSynchronizationSubTypes.CustomInformationSynchronizationSubType
							.ordinal() || size < 1) {
				System.out.println("[Failed]");
				System.out
						.println("+++ Initial negotiations failed. [error code 22]");
				return false;
			}
			if (!sendOrReceive(false, 23, size)) {
				return false;
			}
			String ci = new String(buffer);
			ci = ci.substring(0,ci.indexOf((char)0x00));
			machine.setCustomInformation(ci);
		} while (false);

		return true;
	}

	protected void usage() {
		System.out
				.println("Copyright (C) 2009-2017 Behnam Momeni & Reza MirAskarSHahi. All rights reserved.");
		System.out.println("Partov Project - Version 3.0.5 -- Client Framework");
		System.out
				.println("Code-name: PARTOV (Portable And Reliable Tool fOr Virtualization)");
		System.out.println();
		System.out.println("Usage:");
		System.out.println("  " + "ClientFramework" + " <options>");
		System.out.println("  <options>:");
		System.out
				.println("       --ip <server-ipv4>     The ip (version 4) of the Partov server (like 192.168.0.1)");
		System.out
				.println("       --port <server-port>   The port of the Partov server (like 9339)");
		System.out
				.println("       --map <map-name>       The name of the map/topology which you want to connect to (like router)");
		System.out
				.println("       --user <user-name>     Your username; will be used for authentication.");
		System.out
				.println("       --pass <password>      Your password; will be used for authentication.");
		System.out
				.println("       --node <node-name>     (optional) The name of the node which you want to simulate");
		System.out
				.println("                                         it within <map-name> map (if any)");
		System.out
				.println("       --id <creator-username> (not used in conjunction with --new or --free options)");
		System.out
				.println("                                    Try to connect to the map instance which was created");
		System.out
				.println("                                    by <creator-username> user previously.");
		System.out
				.println("       --new                   (not used in conjunction with --id or --free options)");
		System.out
				.println("                                    Try to create a new map instance.");
		System.out
				.println("                                    Any user can only create (at maximum) one instance of each map.");
		System.out
				.println("       --free                   (not used in conjunction with --id or --new options)");
		System.out
				.println("                                    Free resources of the map instance which was created");
		System.out
				.println("                                    by this user. Any user can only remove his/her owned instances.");
		System.out.println("For any bugs, report to <b_momeni@ce.sharif.edu>");
		System.exit(-1);
	}

	private static void st_run(Machine machine) {
		machine.initialize();
		//synchronized (mutexObject) {
			initialized = true;
		//}
		synchronized(initializationCompletedCondition){
			initializationCompletedCondition.notify();
		}
		machine.run();
	}

	public boolean notifyChangeOfIPAddress(int ip2, int index) {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean notifyChangeOfNetmask(int mask, int index) {
		// TODO Auto-generated method stub
		return false;
	}
}