package ir.sharif.ce.partov.user;

import ir.sharif.ce.partov.utils.Utility;

public class IPv4Header {
	public final static int LEAST_IHL=5;
	public final static short IP_PROTOCOL=0x0800;
	public final static int BROADCAST_IP = 0xFFFF_FFFF;
	public final static int WORD_SIZE = 4;
	private byte[] data;
	
	public IPv4Header() {
		data = new byte[LEAST_IHL * WORD_SIZE];
		setDefaults();
	}
	public IPv4Header(byte[] packet, int pos, int IHL) {
		if(IHL<LEAST_IHL){
			setDefaults();
			data = new byte[LEAST_IHL * WORD_SIZE];
			System.err.println("UN accepatable IHL \nDefault Header Instanced");
		}
		else{
			data = new byte[IHL*4];
			System.arraycopy(packet, pos, data, 0, IHL*WORD_SIZE);
		}
	}
	
	private void setDefaults(){
		setVersion();
		setIHL();
		setDSCP(0);
		setECN(0);
		setTotalLength(getIHL()*WORD_SIZE);
		setDefaultFlags();
		setChecksum((short)0);
		setTTL(0);
		setID(0);
		setProtocol(0);
		setSrc(BROADCAST_IP);
		setDest(BROADCAST_IP);
	}
	private void setVersion(){
		data[0] = (byte)(0x40 + (data[0]&0x0F));
	}
	private void setIHL(){
		data[0] = (byte)((data.length/WORD_SIZE) + (data[0]&0xF0));
	}
	public int getIHL(){
		return (int)(data[0]&0x0F);
	}
	public void setDSCP(int DSCP){
		data[1] = (byte)((DSCP<<2) + (data[1]&0x03));		
	}
	public int getDSCP(){
		return data[1]>>2;		
	}
	public void setECN(int ECN){
		data[1] = (byte)((ECN&0x03) + (data[1]&0xFC));
	}
	public int getECN(){
		return (data[1]&0x3);
	}
	public void setTotalLength(int total_length){
		System.arraycopy(Utility.getBytes((short)total_length), 0, data, 2, 2);
	}
	public int getTotalLength(){
		byte[] total_length= new byte[2];
		System.arraycopy(data, 2, total_length, 0, 2);
		return Utility.convertBytesToShort(total_length);
	}
	public void setID(int Identification){
		System.arraycopy(Utility.getBytes((short)Identification), 0, data, 4, 2);
	}
	public int getID(){
		byte[] ID= new byte[2];
		System.arraycopy(data, 4, ID, 0, 2);
		return Utility.convertBytesToShort(ID);
	}
	public void setDefaultFlags(){
		setReservedFlag(false);
		setDF(false);
		setMF(false);
	}
	public void setReservedFlag(boolean flag){
		data[6] = (byte)((flag?0x80:0x00)+(data[6]&0x7F));		
	}
	public boolean getReservedFlag(){
		return ((data[6]&0x80)!=0);		
	}
	public void setDF(boolean flag){
		data[6] = (byte)((flag?0x40:0x00)+(data[6]&0xBF));		
	}
	public boolean getDF(){
		return ((data[6]&0x40)!=0);		
	}
	public void setMF(boolean flag){
		data[6] = (byte)((flag?0x20:0x00)+(data[6]&0xDF));		
	}
	public boolean getMF(){
		return ((data[6]&0x20)!=0);		
	}
	public void setFragOffset(int FragmentOffset){
		data[6] = (byte)(((FragmentOffset&0x1F00)>>8)+(data[6]&0xE0));
		data[7] = (byte)(FragmentOffset&0xFF);
	}
	public int getFragOffset(){
		return ((data[6]&0x1F)<<8)+(data[7]&0xFF);
	}
	public void setTTL(int TimeToLive){
		data[8] = (byte)(TimeToLive&0xFF);
	}
	public int getTTL(){
		return (int)data[8];
	}
	public void setProtocol(int protocol){
		data[9] = (byte)(protocol&0xFF);
	}
	public int getProtocol(){
		return (int)data[9];
	}
	public void setChecksum(short HeaderChecksum){
		System.arraycopy(Utility.getBytes(HeaderChecksum), 0, data, 10, 2);
	}
	public short getChecksum(){
		byte[] checksum = new byte[2];
		System.arraycopy(data, 10, checksum, 0, 2);
		return Utility.convertBytesToShort(checksum);
	}
	public void setSrc(int IP){
		System.arraycopy(Utility.getBytes(IP), 0, data, 12, 4);
	}
	public int getSrc(){
		byte[] IP = new byte[4];
		System.arraycopy(data, 12, IP, 0, 4);
		return Utility.convertBytesToInt(IP);
	}
	public void setDest(int IP){
		System.arraycopy(Utility.getBytes(IP), 0, data, 16, 4);
	}
	public int getDest(){
		byte[] IP = new byte[4];
		System.arraycopy(data, 16, IP, 0, 4);
		return Utility.convertBytesToInt(IP);
	}
	public byte[] getData(){
		return data;
	}
	public void setData(byte[] data, int pos){
		System.arraycopy(data, 0, this.data, pos, data.length);
	}
}
