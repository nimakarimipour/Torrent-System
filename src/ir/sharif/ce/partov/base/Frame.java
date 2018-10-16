package ir.sharif.ce.partov.base;

public class Frame {
	public int length;
	public byte[] data;

	public Frame(int length,  byte[] data) {
		this.length = length;
		this.data = new byte[length];
		System.arraycopy(data, 0, this.data, 0, length);
	}
	public Frame(byte[] data) {
		this.length = data.length;
		this.data = new byte[length];
		System.arraycopy(data, 0, this.data, 0, length);
	}
}
