package ir.sharif.ce.partov.user;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ir.sharif.ce.partov.base.ClientFramework;
import ir.sharif.ce.partov.base.Frame;
import ir.sharif.ce.partov.base.Machine;
import ir.sharif.ce.partov.utils.Utility;

import static java.lang.Integer.parseInt;
import static debug.print.SimplePrinter.*;
import static ir.sharif.ce.partov.user.BitUtility.*;


public class SimulateMachine extends Machine {

    /**
     * General Properties
     **/
    private boolean isTracker, isPeer;
    private byte[] destMac;

    /**
     * Tracker Properties
     **/
    private HashMap<String, ArrayList<PeerInfo>> torrentsInfo;
    private ArrayList<String> torrentsInfoHash;
    private Pattern pattern;
    private short trackerPort, trackerListeningPort;

    /**
     * Peer Properties
     **/
    private ArrayList<TorrentFile> torrents;
    private ArrayList<String> pendingTrackerInfoHash;
    private ConnectionLog connectionLog;
    private String peerID;
    private int trackerIP;
    private short peerPort;
    private Command[] commands;


    public SimulateMachine(ClientFramework clientFramework, int count) {
        super(clientFramework, count);
    }


    public void initialize() {
        print("Defining type of machine...");
        findType();

    }

    private void findType() {
        String[] infos = getCustomInformation().split("\n");
        if (infos[0].startsWith("Tracker Info:")) {
            print("Is a tracker");
            isTracker = true;
            initializeTracker();
            extractTrackerInfo(infos);
        }
        if (infos[0].startsWith("Peer Info:")) {
            print("Is a peer");
            isPeer = true;
            initializePeer();
            extractPeerInfo(infos);
        }
    }

    private void initializeTracker() {
        pattern = Pattern.compile("GET /announce\\?info_hash=(.*)&peer_id=(.*)&port=(\\d+) HTTP/1\\.1");
        torrentsInfo = new HashMap<>();
        torrentsInfoHash = new ArrayList<>();
    }

    private void initializePeer() {
        pendingTrackerInfoHash = new ArrayList<>();
        connectionLog = new ConnectionLog();
        setUpCommands();
    }

    private void setUpCommands() {
        commands = new Command[9];
        commands[0] = new Command("check (\\d+) of (\\d+)", data -> checkPieceNumber(parseInt(data.group(1)), parseInt(data.group(2))));
        commands[1] = new Command("check all of (\\d+)", data -> checkAllPieces(parseInt(data.group(1))));
        commands[2] = new Command("get peers of (\\d+)", data -> getPeers(parseInt(data.group(1))));
        commands[3] = new Command("connect to (.*) from (\\d+)", data -> connect(data.group(1), parseInt(data.group(2))));
        commands[4] = new Command("unchoke to (.*) of (\\d+)", data -> unchoke(data.group(1), parseInt(data.group(2))));
        commands[5] = new Command("choke to (.*) of (\\d+)", data -> choke(data.group(1), parseInt(data.group(2))));
        commands[6] = new Command("get interested to (.*) of (\\d+)", data -> getInterested(data.group(1), parseInt(data.group(2))));
        commands[7] = new Command("get uninterested to (.*) of (\\d+)", data -> getUninterested(data.group(1), parseInt(data.group(2))));
        commands[8] = new Command("download piece (\\d+) from (.*) of (\\d+)", data -> download(parseInt(data.group(1)), data.group(2), parseInt(data.group(3))));
    }

    private void extractPeerInfo(String[] infos) {
        print("Extracting peer info");
        peerID = infos[1];
        peerPort = Short.parseShort(infos[2].substring(16));
        trackerIP = Utility.getIP(infos[3].substring(0, infos[3].indexOf(":")));
        trackerListeningPort = Short.parseShort(infos[3].substring(infos[3].indexOf(":") + 1));
        torrents = new ArrayList<>();
        int numOfFiles = Integer.parseInt(infos[4]);
        for (int i = 0; i < numOfFiles; i++) {
            String hashInfo = infos[(i * 6) + 5].substring(11);
            int fileSize = Integer.parseInt(infos[(i * 6) + 6].substring(11));
            int peaceSize = Integer.parseInt(infos[(i * 6) + 7].substring(12));
            String crc = infos[(i * 6) + 8].substring(13);
            String hash = infos[(i * 6) + 9].substring(6);
            String data = infos[(i * 6) + 10].substring(6);
            torrents.add(new TorrentFile(data, hash, hashInfo, fileSize, peaceSize, crc));
        }
        destMac = Utility.getMac(infos[infos.length - 1].substring(17));
    }

    private void extractTrackerInfo(String[] infos) {
        print("Extracting tracker info");
        trackerPort = Short.parseShort(infos[1].substring(16));
        int numOfFiles = Integer.parseInt(infos[2]);
        for (int i = 0; i < numOfFiles; i++) {
            String infoHash = infos[3 + i].substring(infos[3 + i].indexOf(":") + 2);
            torrentsInfo.put(infoHash, new ArrayList<>());
            torrentsInfoHash.add(infoHash);
        }
        destMac = Utility.getMac(infos[infos.length - 1].substring(17));
    }


    public void processFrame(Frame frame, int ifaceIndex) {
        byte[] data = new byte[frame.data.length];
        System.arraycopy(frame.data, 0, data, 0, data.length);
        print("Frame received at iface " + ifaceIndex + " with length " + frame.length);

        EthernetHeader eth = new EthernetHeader(data, 0);
        print("type of ethernet packet is 0x" + Utility.byteToHex(eth.getTypeinBytes()[0]) + Utility.byteToHex(eth.getTypeinBytes()[1]));
        if (eth.getTypeinInt() == ((int) IPv4Header.IP_PROTOCOL)) {
            IPv4Header iph = new IPv4Header(data, 14, 5);
            print("Source IP: " + Utility.getIPString(iph.getSrc()));
            print("Destination IP: " + Utility.getIPString(iph.getDest()));
            TCPHeader tcpHeader = new TCPHeader(frame.data, 34);
            print("Source Port: " + tcpHeader.getSrcPort());
            byte[] payload = new byte[frame.length - 54];
            System.arraycopy(frame.data, 54, payload, 0, payload.length);
            if (isPeer) processFrameOfPeer(iph, tcpHeader, payload);
            if (isTracker) processFrameOfTracker(iph, payload);
        }
    }


    public void run() {
        Scanner s = new Scanner(System.in);
        if (isTracker) runTracker();
        if (isPeer) runPeer(s);
        print("No especial type found for device.\nTerminating program...");
    }


    private void processFrameOfTracker(IPv4Header iph, byte[] payload) {
        print("In Process Frame of tracker.");
        print("The message is: " + bytesToString(payload));
        Matcher m = pattern.matcher(bytesToString(payload).split("\n")[0]);
        if (m.matches()) {
            print("The message matches the type GET /announce");
            PeerInfo p = new PeerInfo(m.group(2), iph.getSrc(), Short.parseShort(m.group(3)));
            ArrayList<PeerInfo> peerInfos = torrentsInfo.get(m.group(1));
            print("Wants the peers of torrent with info hash: " + m.group(1) + " and the result is: " + peerInfos);
            sendTorrentInfoToPeer(m.group(1), p, peerInfos);
            if (!peerInfos.contains(p)) {
                System.out.println("new peer " + p.peerID + " added to torrent " + findTorrentNumber(m.group(1), torrentsInfoHash));
                peerInfos.add(p);
            } else print("Already have that peer for infoHash: " + m.group(1));
        } else print("The message did not match the protocol");
    }

    @SuppressWarnings("ConstantConditions")
    private void processFrameOfPeer(IPv4Header iph, TCPHeader tcph, byte[] payload) {
        print("In Process frame of peer.");
        if (iph.getSrc() == trackerIP) {
            print("The message is from tracker.");
            String text = bytesToString(payload);
            if (text.startsWith("HTTP/1.1 200 OK\nInterval: 1000s")) {
                print("The message confirms the protocol.");
                String[] lines = text.split("\n");
                String infoHash = lines[2].substring(lines[2].indexOf(":") + 2);
                int numOfTorrent = findTorrentNumber(infoHash);
                if (numOfTorrent != -1) {
                    if (!pendingTrackerInfoHash.contains(infoHash)) {
                        print("we did'nt ask for this info hash: " + infoHash);
                        return;
                    }
                    pendingTrackerInfoHash.remove(infoHash);
                    print("We were waiting fot infoHash: " + infoHash + " From tracker. adding the peers." + " lines length: " + lines.length);
                    for (int i = 3; i < lines.length; i++) {
                        print("Adding number: " + i);
                        String[] infos = lines[i].split(" ");
                        PeerInfo p = new PeerInfo(infos[0], Utility.getIP(infos[1]), Short.parseShort(infos[2]));
                        addPeerToList(p, infoHash);
                    }
                    print("Done adding to list of peers of torrent: " + infoHash);
                } else print("We don't have the torrent with info hash: " + infoHash);
            }
        } else {
            print("The message is from a peer");
            processP2PFrame(iph, tcph, payload);
        }
    }

    private void processP2PHandShakeFrame(IPv4Header iph, TCPHeader tcph, byte[] payload) {
        String text = bytesToString(payload);
        String peerID = text.substring(48);
        peerID = clearSpacesFromEnd(peerID);
        String infoHash = text.substring(28, 32);
        TorrentFile t = findTorrent(infoHash);
        System.out.println("bittorrent handshake packet received from " + peerID);
        if (t == null) {
            print("We don't have that torrent.");
            return;
        }
        PeerInfo p = new PeerInfo(peerID, iph.getSrc(), tcph.getSrcPort());
        print("Handshake from peer with IP: " + Utility.getIPString(p.ip) + " " + p.port + " in tcph: " + tcph.getSrcPort());
        if (t.isPendingHandShake(peerID)) {
            print("We were waiting for the handshake.");
            t.removePendingHandshaking(peerID);

        } else {
            print("We were'nt waiting for a handshake need to respond it.");
            addPeerToList(p, infoHash);
            sendHandShake(p, infoHash);
        }
        connectionLog.connect(infoHash, p);
        t.getConnected(peerID);
    }

    private void processP2PFrame(IPv4Header iph, TCPHeader tcph, byte[] payload) {
        if (payload[0] == 19 && isBittorrentProtocol(payload)) {
            print("It is a handshake message");
            processP2PHandShakeFrame(iph, tcph, payload);
        } else {
            print("Not a handshake message");
            switch (payload[4]) {
                case 0:
                    chokeRespond(iph);
                    break;
                case 1:
                    unchokeRespond(iph);
                    break;
                case 2:
                    interestedRespond(iph);
                    break;
                case 3:
                    notInterestedRespond(iph);
                    break;
                case 6:
                    downloadRespond(iph, payload);
                    break;
                case 7:
                    receivePieceRespond(iph, payload);
                    break;
                default:
                    print("Undefined mode.");
            }
        }
    }

    private void receivePieceRespond(IPv4Header iph, byte[] payload) {
        PeerInfo p = connectionLog.getPeerByIP(iph.getSrc());
        TorrentFile t = findTorrent(connectionLog.getInfoHashByPeer(p));
        if (t == null) {
            print("We are not connected to the requested peer with this info hash");
            return;
        }
        print("Replacing data...");
        byte[] indexBytes = new byte[4];
        System.arraycopy(payload, 5, indexBytes, 0, 4);
        int index = Utility.convertBytesToInt(indexBytes);
        byte[] sizeBytes = new byte[4];
        System.arraycopy(payload, 0, sizeBytes, 0, 4);
        int size = Utility.convertBytesToInt(sizeBytes) - 9;
        byte[] data = new byte[size];
        System.arraycopy(payload, 13, data, 0, data.length);
        t.replacePiece(data, index);
        print("Data replaced at index: " + index + " of torrent: " + t.infoHash);
    }

    private void downloadRespond(IPv4Header iph, byte[] payload) {
        PeerInfo p = connectionLog.getPeerByIP(iph.getSrc());
        TorrentFile t = findTorrent(connectionLog.getInfoHashByPeer(p));
        if (t == null) {
            print("We are not connected to the requested peer with this info hash");
            return;
        }
        if (t.isChoked(p.peerID)) System.out.println("we are choked to " + p.peerID);
        else {
            print("Printing torrent info.");
            byte[] indexBytes = new byte[4];
            System.arraycopy(payload, 5, indexBytes, 0, 4);
            int index = Utility.convertBytesToInt(indexBytes);
            if (t.isCorrect(index)) {
                byte[] piece = stringToBytes(t.getPiece(index));
                byte[] downloadPayload = new byte[13 + piece.length];
                byte[] length = Utility.getBytes(9 + piece.length);
                System.arraycopy(length, 0, downloadPayload, 0, 4);
                downloadPayload[4] = 7;
                System.arraycopy(indexBytes, 0, downloadPayload, 5, 4);
                System.arraycopy(piece, 0, downloadPayload, 13, piece.length);
                sendTo(p.ip, peerPort, p.port, downloadPayload);
            } else print("Data is not correct.");
        }
    }

    private void notInterestedRespond(IPv4Header iph) {
        PeerInfo p = connectionLog.getPeerByIP(iph.getSrc());
        if (p == null) {
            print("Unknown IP.");
            return;
        }
        System.out.println(p.peerID + " is not interested");
    }

    private void interestedRespond(IPv4Header iph) {
        PeerInfo p = connectionLog.getPeerByIP(iph.getSrc());
        if (p == null) {
            print("Unknown IP.");
            return;
        }
        System.out.println(p.peerID + " is interested");
    }

    private void unchokeRespond(IPv4Header iph) {
        PeerInfo p = connectionLog.getPeerByIP(iph.getSrc());
        if (p == null) {
            print("Unknown IP.");
            return;
        }
        System.out.println(p.peerID + " unchoked");
    }

    private void chokeRespond(IPv4Header iph) {
        PeerInfo p = connectionLog.getPeerByIP(iph.getSrc());
        if (p == null) {
            print("Unknown IP.");
            return;
        }
        System.out.println(p.peerID + " choked");
    }

    @SuppressWarnings({"InfiniteLoopStatement", "StatementWithEmptyBody"})
    private void runTracker() {
        print("Running Tracker...");
        while (true) ;
    }


    @SuppressWarnings("InfiniteLoopStatement")
    private void runPeer(Scanner s) {
        print("Running Peer...");
        String command;
        while (true) {
            command = s.nextLine();
            Command c = findCommand(command);
            if(c == null) System.out.println("invalid command");
            else c.execute(c.getMatcher());
        }
    }


    private void download(Integer pieceNum, String peerID, Integer torrentNum) {
        TorrentFile t = torrents.get(torrentNum);
        PeerInfo p = t.findPeer(peerID);
        if (p == null) {
            System.out.println("unregistered peer id");
            return;
        }
        if (!t.isConnected(peerID)) {
            System.out.println("we are not connected");
            return;
        }
        if (!t.isInterested(peerID)) {
            System.out.println("we are not interested");
            return;
        }
        byte[] payload = new byte[17];
        byte[] indexBytes = Utility.getBytes(pieceNum);
        byte[] sizeBytes = Utility.getBytes(t.getPieceSize());
        payload[3] = 13;
        payload[4] = 6;
        System.arraycopy(indexBytes, 0, payload, 5, 4);
        System.arraycopy(sizeBytes, 0, payload, 13, 4);
        sendTo(p.ip, peerPort, p.port, payload);
        System.out.println("the piece requested");
    }

    private void choke(String peerID, Integer num) {
        torrents.get(num).chock(peerID);
        byte[] payload = new byte[5];
        payload[3] = 1;
        PeerInfo p = torrents.get(num).findPeer(peerID);
        if (p == null) {
            System.out.println("unregistered peer id");
            return;
        }
        sendTo(p.ip, peerPort, p.port, payload);
    }

    private void unchoke(String peerID, Integer num) {
        torrents.get(num).unchoke(peerID);
        byte[] payload = new byte[5];
        payload[3] = 1;
        payload[4] = 1;
        PeerInfo p = torrents.get(num).findPeer(peerID);
        if (p == null) {
            System.out.println("unregistered peer id");
            return;
        }
        sendTo(p.ip, peerPort, p.port, payload);
    }

    private void connect(String peerID, Integer numOfTorrent) {
        PeerInfo p = torrents.get(numOfTorrent).findPeer(peerID);
        if (p == null) {
            System.out.println("unregistered peer id");
            return;
        }
        String infoHash = torrents.get(numOfTorrent).infoHash;
        torrents.get(numOfTorrent).addPendingHandshaking(peerID);
        sendHandShake(p, infoHash);
    }

    private void getPeers(Integer i) {
        String payload = "GET /announce?info_hash=" + torrents.get(i).infoHash + "&peer_id=" +
                peerID + "&port=" + peerPort + " HTTP/1.1\nHost: " + Utility.getIPString(trackerIP);
        pendingTrackerInfoHash.add(torrents.get(i).infoHash);
        sendTo(trackerIP, (short) 80, trackerListeningPort, payload.getBytes());
    }

    private void getUninterested(String peerID, Integer num) {
        torrents.get(num).getUninterested(peerID);
        byte[] payload = new byte[5];
        payload[3] = 1;
        payload[4] = 3;
        PeerInfo p = torrents.get(num).findPeer(peerID);
        if (p == null) {
            System.out.println("unregistered peer id");
            return;
        }
        sendTo(p.ip, peerPort, p.port, payload);
    }

    private void getInterested(String peerID, Integer num) {
        torrents.get(num).getInterested(peerID);
        byte[] payload = new byte[5];
        payload[3] = 1;
        payload[4] = 2;
        PeerInfo p = torrents.get(num).findPeer(peerID);
        if (p == null) {
            System.out.println("unregistered peer id");
            return;
        }
        sendTo(p.ip, peerPort, p.port, payload);
    }

    private void checkPieceNumber(Integer pieceNumber, Integer numOfTorrent) {
        boolean isCorrect = torrents.get(numOfTorrent - 1).checkPieceNumber(pieceNumber);
        if (isCorrect) System.out.println(pieceNumber + " data hash code matched");
        else System.out.println(pieceNumber + " data hash code did not match");
    }

    private void checkAllPieces(Integer torrentNum) {
        int ans = torrents.get(torrentNum).checkAllPieces();
        System.out.println("we have " + ans + " piece(s)");
    }


    private void sendTo(int ip, short srcPort, short destPort, byte[] payload) {
        print("Sending packet to IP: " + Utility.getIPString(ip) + " and port: " + destPort + " From port: " + srcPort);
        EthernetHeader eth = new EthernetHeader();
        eth.setDest(destMac);
        eth.setSrc(iface[0].mac);
        byte[] ether_type = {8, 0};
        eth.setType(ether_type);
        IPv4Header iph = new IPv4Header();
        iph.setDest(ip);
        iph.setSrc(iface[0].ip);
        iph.setTotalLength(TCPHeader.TCP_LENGTH + payload.length + 20);
        iph.setProtocol(6);
        TCPHeader tcp = new TCPHeader();
        tcp.setDestPort(destPort);
        tcp.setSrcPort(srcPort);
        byte[] message = new byte[payload.length + 54];
        System.arraycopy(eth.getData(), 0, message, 0, 14);
        System.arraycopy(iph.getData(), 0, message, 14, 20);
        System.arraycopy(tcp.getData(), 0, message, 34, 20);
        System.arraycopy(payload, 0, message, 54, payload.length);
        Frame f = new Frame(message);
        sendFrame(f, 0);
        print("Sent.");
    }

    private void sendHandShake(PeerInfo p, String infoHash) {
        byte[] handShakePayload = new byte[68];
        handShakePayload[0] = 19;
        byte[] protocol = "BitTorrent protocol".getBytes();
        System.arraycopy(protocol, 0, handShakePayload, 1, protocol.length);
        System.arraycopy(infoHash.getBytes(), 0, handShakePayload, 28, 4);
        System.arraycopy(peerID.getBytes(), 0, handShakePayload, 48, peerID.getBytes().length);
        sendTo(p.ip, peerPort, p.port, handShakePayload);
        System.out.println("bittorrent handshake packet sent to " + p.peerID);
    }

    private void sendTorrentInfoToPeer(String infoHash, PeerInfo p, ArrayList<PeerInfo> list) {
        String text = "HTTP/1.1 200 OK\nInterval: 1000s\ninfo hash: " + infoHash;
        for (PeerInfo peer : list) {
            if (!peer.equals(p))
                text += "\n" + peer.peerID + " " + Utility.getIPString(peer.ip) + " " + peer.port;
        }
        byte[] payload = text.getBytes();
        print("Torrent info text is: ");
        print(text);
        print("Ended\n");
        sendTo(p.ip, trackerPort, (byte) 80, payload);
    }


    private Command findCommand(String command) {
        for(Command c : commands){
            if(c.commandConfirms(command)) return c;
        }
        return null;
    }

    private void addPeerToList(PeerInfo p, String infoHash) {
        print("Adding peer to the torrent: " + infoHash);
        ArrayList<PeerInfo> peers;
        TorrentFile t = findTorrent(infoHash);
        if (t == null) {
            print("we don't have torrent with this info hash");
            return;
        }
        peers = t.peers;
        if (!peers.contains(p)) {
            peers.add(p);
            System.out.println("new peer " + p.peerID + " added to torrent " + findTorrentNumber(infoHash));
        } else print("Already have that peer.");
    }

    private int findTorrentNumber(String infoHash) {
        for (int i = 0; i < torrents.size(); i++) {
            if (torrents.get(i).infoHash.equals(infoHash)) return (i + 1);
        }
        return -1;
    }

    private int findTorrentNumber(String name, ArrayList<String> list) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).equals(name)) return (i + 1);
        }
        return -1;
    }

    private TorrentFile findTorrent(String infoHash) {
        for (TorrentFile torrent : torrents) {
            if (torrent.infoHash.equals(infoHash)) return torrent;
        }
        return null;
    }

    private String clearSpacesFromEnd(String peerID) {
        int index = peerID.length() - 1;
        while (peerID.charAt(index) == ' ') --index;
        return peerID.substring(0, index + 1);
    }
}


class TorrentFile {

    private String crc;
    private String hash;
    private StringBuilder data;
    private boolean[] isCorrect;
    private int pieceSize;
    private ArrayList<String> unChokedPeers;
    private ArrayList<String> interestedPeers;
    private ArrayList<String> handShakePending;
    private ArrayList<String> connectedPeers;

    ArrayList<PeerInfo> peers;
    String infoHash;

    TorrentFile(String data, String hash, String infoHash, int fileSize, int pieceSize, String crc) {
        this.data = new StringBuilder(data);
        this.hash = hash;
        this.infoHash = infoHash;
        this.pieceSize = pieceSize;
        this.crc = crc;
        isCorrect = new boolean[fileSize / pieceSize];
        peers = new ArrayList<>();
        unChokedPeers = new ArrayList<>();
        interestedPeers = new ArrayList<>();
        handShakePending = new ArrayList<>();
        connectedPeers = new ArrayList<>();
    }

    boolean checkPieceNumber(int i) {
        if (isCorrect[i]) return true;
        int crc = findCrc(i);
        int realCrc = Integer.parseInt("" + hash.charAt(i), 16);
        if (crc == realCrc) {
            isCorrect[i] = true;
            return true;
        }
        return false;
    }

    int checkAllPieces() {
        int ans = 0;
        for (int i = 0; i < isCorrect.length; i++) {
            if (!isCorrect[i]) {
                if (checkPieceNumber(i)) {
                    isCorrect[i] = true;
                    ++ans;
                }
            } else ++ans;
        }
        return ans;
    }

    PeerInfo findPeer(String peerID){
        for(PeerInfo p : peers) if(p.peerID.equals(peerID)) return p;
        return null;
    }


    void chock(String peerID){
        unChokedPeers.remove(peerID);
    }

    void unchoke(String peerID){
        unChokedPeers.add(peerID);
    }

    void getInterested(String peerID){
        interestedPeers.add(peerID);
    }

    void getUninterested(String peerID){
        interestedPeers.remove(peerID);
    }

    void addPendingHandshaking(String peerID){
        handShakePending.add(peerID);
    }

    void removePendingHandshaking(String peerID){
        handShakePending.remove(peerID);
    }

    void getConnected(String peerID){
        if(!connectedPeers.contains(peerID)) connectedPeers.add(peerID);
    }

    void replacePiece(byte[] bytes, int index){
        String piece = "";
        for(byte b : bytes) piece += byteToString(b);
        piece = new BigInteger(piece, 2).toString(16);
        data.replace(index * 2 * pieceSize, (index + 1) * 2 * pieceSize, piece);
        isCorrect[index] = true;
    }

    boolean isConnected(String peerID){
        return connectedPeers.contains(peerID);
    }

    boolean isInterested(String peerID){
        return interestedPeers.contains(peerID);
    }

    boolean isChoked(String peerID){
        return !unChokedPeers.contains(peerID);
    }

    boolean isPendingHandShake(String peerID){
        return handShakePending.contains(peerID);
    }


    private int findCrc(int i) {
        int index = 0;
        StringBuilder piece = new StringBuilder(getPiece(i) + "0000");
        while (index < piece.length() - 4) {
            while (index < piece.length() && piece.charAt(index) == '0') ++index;
            if (index < piece.length() - 4) {
                piece.replace(index, index + 5, xor(piece.substring(index, index + 5), crc));
            }
        }
        return readString(piece.substring(piece.length() - 5));
    }

    private String xor(String s1, String s2) {
        String ans = "";
        for (int i = 0; i < s1.length(); i++) {
            if (s1.charAt(i) == s2.charAt(i)) ans += "0";
            else ans += "1";
        }
        return ans;
    }

    int getPieceSize() {
        return pieceSize;
    }

    String getPiece(int index){
        String ans = new BigInteger(data.substring(index * 2 * pieceSize, (index + 1) * 2 * pieceSize), 16).toString(2);
        int padding = ans.length() % 4;
        if(padding == 0) return ans;
        padding = 4 - padding;
        for (int i = 0; i < padding; i++) ans = "0" + ans;
        return ans;
    }

    public String toString(){
        String ans = "";
        ans += "Info Hash: " + infoHash + "\n" +
                "Data Length: " + data.length() + "  and the data is: \n" + data + "\n" +
                "CRC: " + crc + "\n" +
                "Piece Size: " + pieceSize + "\n" +
                "Hash: " + hash;
        return ans;
    }

    boolean isCorrect(int index) {
        return isCorrect[index];
    }
}

class PeerInfo {
    String peerID;
    int ip;
    short port;

    PeerInfo(String peerID, int ip, short port) {
        this.peerID = peerID;
        this.ip = ip;
        this.port = port;
    }

    public boolean equals(Object o) {
        if (o == null) return false;
        if (o.getClass() != this.getClass()) return false;
        PeerInfo other = (PeerInfo) o;
        return this.peerID.equals(other.peerID) &&
                this.port == other.port &&
                this.ip == other.ip;
    }

    public String toString() {
        return "PeerID: " + peerID + " IP: " + Utility.getIPString(ip) + " Port: " + port;
    }
}

class BitUtility {

    static boolean isBittorrentProtocol(byte[] payload) {
        if(1 + "BitTorrent protocol".length() - 1 >= payload.length) return false;
        byte[] bytes = "BitTorrent protocol".getBytes();
        for (int j = 0; j < "BitTorrent protocol".length(); j++) {
            if(payload[1 + j] != bytes[j]) return false;
        }
        return true;
    }

    static String bytesToString(byte[] bytes) {
        String ans = "";
        for (byte b : bytes)
            if (b != 0) ans += (char) b;
            else ans += " ";
        return ans;
    }

    static String byteToString(byte b) {
        return String.format("%8s", Integer.toBinaryString(((int) b + 256) % 256)).replace(' ', '0');
    }

    static byte readString(String s) {
        return (byte) (int) Integer.valueOf(s, 2);
    }

    static byte[] stringToBytes(String s){
        byte[] ans = new byte[s.length() / 8];
        for (int i = 0; i < ans.length; i++) {
            ans[i] = readString(s.substring(i * 8, (i + 1) * 8));
        }
        return ans;
    }
}

class ConnectionLog{

    private HashMap<PeerInfo, String> connections;

    ConnectionLog(){
        connections = new HashMap<>();
    }

    void connect(String infoHash, PeerInfo peer){
        connections.put(peer, infoHash);
    }

    PeerInfo getPeerByIP(int ip){
        for(PeerInfo p : connections.keySet()){
            if(p.ip == ip) return p;
        }
        return null;
    }

    String getInfoHashByPeer(PeerInfo p){
        return connections.get(p);
    }
}

class TCPHeader {

    final static int TCP_LENGTH = 20;

    private byte[] data;


    TCPHeader(byte[] data, int pos){
        this.data = new byte[TCP_LENGTH];
        System.arraycopy(data, pos, this.data, 0, TCP_LENGTH);
        setDefaults();
    }

    TCPHeader(){
        data = new byte[TCP_LENGTH];
        setDefaults();
    }


    private void setDefaults() {
        data[12] = (short)80;
    }


    void setSrcPort(short srcPort){
        byte[] bytes = Utility.getBytes(srcPort);
        data[0] = bytes[0];
        data[1] = bytes[1];
    }

    void setDestPort(short destPort){
        byte[] bytes = Utility.getBytes(destPort);
        data[2] = bytes[0];
        data[3] = bytes[1];
    }


    short getSrcPort(){
        byte[] srcPortBytes = new byte[2];
        System.arraycopy(data, 0, srcPortBytes, 0, 2);
        return Utility.convertBytesToShort(srcPortBytes);
    }

    byte[] getData(){
        return data;
    }
}

class Command implements Order{

    private Matcher matcher;
    private Pattern pattern;
    private Order order;


    Command(String cp, Order order) {
        pattern = Pattern.compile(cp);
        this.order = order;
    }

    boolean commandConfirms(String command){
        matcher = pattern.matcher(command);
        return matcher.matches();
    }

    Matcher getMatcher(){
        return matcher;
    }

    @Override
    public void execute(Matcher data) {
        order.execute(data);
    }
}

interface Order{
    void execute(Matcher data);
}