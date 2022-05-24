package securehashing;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;
 
public class AES {
	private String plainText;
	private String key;
	
	private static int[] box = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
	
	public AES(String plainText, String key) {
		this.plainText = plainText;
		this.key = key;
	}
	
	private static String convertTokenKey(String key) {
		String convertedKey;
		int time = Integer.parseInt(key);
		time = time / 30;
//        time = time / 4;
//        time = time * 4;
		time = (int) Math.floor(time);
        int bt = time & 0xFF;
        time = time << 8;
        time = time | bt;
        //<<32 moves it 8 0's to the right
//        int time64 = time;
//        time = time << 32;
//        time = time | time64;
//        
        //java does not handle the 16-nibble hex, so we have to store as a string
        convertedKey = Integer.toHexString(time)+Integer.toHexString(time);
        
		return convertedKey;
	}
	
	//Performs the xor operation on the bits of each hex element
	private static String[] xor(String[] hexK, String[] hexP) {
		String[] addedRk = new String[hexK.length];
		for(int i = 0; i<hexK.length; i++) {
			//^ is the xor operation
			addedRk[i] = Integer.toHexString(Integer.parseInt(hexK[i], 16) ^ Integer.parseInt(hexP[i],16));
			//prepends a 0 if the hex is only one unit long
			if(addedRk[i].length()==1) {
				addedRk[i] = '0'+addedRk[i];
			}
		}
			return addedRk;
	}
	
	//Substitutes each byte in the state matrix with corresponding entry in the AES S-Box
	private static String[] sBox(String[] aRk) {
		String[] sub = new String[aRk.length];
		int len = (int) Math.sqrt(aRk.length);
		
		//converts the 1d sbox as a 2d array
		int[][] sqBx = new int[16][16];
		for(int i = 0; i<16; i++) {
			for(int j = 0; j<16; j++) {
				sqBx[i][j] = box[16*i + j];
				//System.out.println(Integer.toHexString(sqBx[i][j]));
			}
			
		}
		
		//Because the sbox has number conversions for numbers 0-9 and then the letters a-f go in 10-15,
		//it is easier to map the letters to numbers, and the numbers 0-9 to 0-9 by using indexOf
//		HashMap<String, Integer> table= new HashMap<String, Integer>();
//		char start = 'a';
//		
//		for(int i = 0; i<17; i++) {
//			if(i<10) {
//				table.put(i+"", i);
//			} else {
//				table.put(start+"", i);
//				start = (char) (start+1);
//			}
//		}
		String digits = "0123456789abcdef";		
		for(int i = 0; i<aRk.length; i++) {
			if(aRk[i].length() == 1) {
				aRk[i] = "0" + aRk[i];
			}
			//int row = table.get(aRk[i].substring(0,1));
			int row = digits.indexOf(aRk[i].substring(0,1));
			//int col = table.get(aRk[i].substring(1,2));
			int col = digits.indexOf(aRk[i].substring(1,2));
			sub[i] = Integer.toHexString(sqBx[row][col]);
			
			if(sub[i].length() == 1) {
				sub[i] = "0"+sub[i];
			}
			
		}
		return sub;
	}
	
	
	//Shifts the elements in each row based on their row number [0th row is shifted 0 times, 1st row
	//shifted once to the left, second shifted twice to the left, and third shifted thrice to the left
	private static String[] shiftRow(String[] sB) {
		String[] rowOrd = new String[sB.length];
		String[][] fbf = new String[4][4];
		
		for(int i=0; i<4; i++) {
			for(int j=0; j<4; j++) {
				fbf[i][j] = sB[4*j + i];
			}
		}
				
		for(int i=0; i<4; i++) {
			for(int k=0; k<i; k++) {
					String temp = fbf[i][3];
					fbf[i][3] = fbf[i][0];
					fbf[i][0] = fbf[i][1];
					fbf[i][1] = fbf[i][2];
					fbf[i][2] = temp;
				}
			
		}
		
		for(int i=0; i<4; i++) {
			for(int j=0; j<4; j++) {
				rowOrd[4*i + j]=(fbf[j][i]);
			}
		}
				
		return rowOrd;
		
	}
	
	// the reason why some of these lines are complex is because java does not store 
	// hex as 0x05 and instead stores as 0x5, but 0x05 is needed for some of the calculations to
	// work, thus the hexes must be stored in the string format in order to prepend that 0
	// but storing them as strings results in these complex in inside a string inside an int lines
	private static String[] mixCol(String[] sR) {
		String[] mixedCol = new String[sR.length];
		String[][] squ = new String[4][4];
		
		for(int i=0; i<4; i++) {
			for(int j=0; j<4; j++) {
				String val = Integer.toBinaryString(Integer.parseInt(sR[4*j + i], 16));
				if(val.length() < 8){
					squ[i][j] = String.format("%08d", Integer.parseInt(val));
				}
				else {squ[i][j] = val;}
			}
		}
		
		int[][] fixed = {{02, 03, 01, 01}, 
						 {01, 02, 03, 01},
						 {01, 01, 02, 03},
						 {03, 01, 01, 02}};
		
		String[][] result = new String[4][4];
		Queue<Integer> res = new LinkedList<Integer>();
		
		
		for(int i = 0; i<4; i++) {
			for(int j=0; j<4; j++) {
				
				for(int k = 0; k<4; k++) {
					if(fixed[i][k] == 1) {
						res.add(Integer.parseInt(squ[k][j], 2));
					}
					if(fixed[i][k] == 2 || fixed[i][k] == 3) {
						String replacement = (squ[k][j]).substring(1) + "0";
						if(squ[k][j].substring(0,1).contentEquals("1")) {
							int firstStep = (Integer.parseInt(Integer.toBinaryString((Integer.parseInt(replacement, 2) ^ 0x1b))));

							if(fixed[i][k] == 2) { res.add(Integer.parseInt(Integer.toString(firstStep), 2));
							}
							else {
								res.add(Integer.parseInt(Integer.toString(firstStep),2) ^ Integer.parseInt(squ[k][j], 2));
							}
						}
						else {
							int alternative = (Integer.parseInt(replacement,2));
							if(fixed[i][k] == 2) { 
									res.add(Integer.parseInt(Integer.toBinaryString(alternative),2));
								}
							
							else {res.add(Integer.parseInt(Integer.toBinaryString(alternative ^ Integer.parseInt(squ[k][j], 2)),2));}
						}
					}
				}
				
				
				int firstElement = res.remove();
				while(!res.isEmpty()) {
					firstElement ^= res.remove();
								
					//System.out.println(Integer.toBinaryString(res.remove()));
				}
				result[i][j] = Integer.toHexString(firstElement);
			}
		}
//		for(int i = 0; i<64; i++) {
//			System.out.println("ggggg" + res.get(i));
//		}
		//System.out.println(171 ^ Integer.parseInt("10011011",2));
		//String answer = "g";
		//System.out.printf("%x%n", answer); c6 8d
		//String p = String.format("%08d", 11111);
		//System.out.println(Integer.toBinaryString(Integer.parseInt("01100011",2) * Integer.parseInt("10",2)));
		//System.out.println(Integer.parseInt("01100011",2) * 0x02);
		
		
		for(int i=0; i<4; i++) {
			for(int j=0; j<4; j++) {
				if(result[i][j].length() == 1) {result[i][j] = "0"+ result[i][j];}
				mixedCol[4*j + i]=(result[i][j]);
			}
		}
		
		return mixedCol;
		
	}
	
	private static int roundConstant(int roundNum) {
		if(roundNum == 1) {return 0x01;}
		if(roundConstant(roundNum-1) < 0x80 ) { return  (2*roundConstant(roundNum-1));}
		else return  ( (2*roundConstant(roundNum-1))^0x11B);
	}
	
	//performs the key expansion	
	private static String[] roundkeyCalculator(String[] startKey, int keyNum, int roundNum) {
		if(keyNum == 0) {return startKey;} //remember that this startkey is not necessarily the first roundkey
		String[] key = new String[16];
		/**
		 * Psuedocode:
		 * 
		 * split the first roundkey into 4
		 * g-ify and calculate w4, w5, w6 and w7
		 * set key equal to the combination of all four of these little arrays
		 * 
		 */
				
		String[] w0  = new String[4], w1 = new String[4], w2 = new String[4], w3 = new String[4],
				w4 = new String[4], w5 = new String[4], w6 = new String[4], w7 = new String[4];
		for(int i=0; i<4; i++) {
			w0[i]=startKey[i];
			w1[i] = startKey[i+4];
			w2[i] = startKey[i+8];
			w3[i] = startKey[i+12];
		}
		String[] gw3 = {w3[1], w3[2], w3[3], w3[0]}; 
		gw3 = sBox(gw3);
		
		
//		int rc = 0;
//		if(roundNum == 1) {rc = 0x01;}
//		if(roundNum == 2) {rc = 0x02;}
//		if(roundNum == 3) {rc = 0x04;}
//		if(roundNum == 4) {rc = 0x08;}
//		if(roundNum == 5) {rc = 0x10;}
//		if(roundNum == 6) {rc = 0x20;}
//		if(roundNum == 7) {rc = 0x40;}
//		if(roundNum == 8) {rc = 0x80;}
//		if(roundNum == 9) {rc = 0x1B;}
//		if(roundNum == 10) {rc = 0x36;}
//		
		gw3[0] = Integer.toHexString(Integer.parseInt(gw3[0], 16) ^ roundConstant(roundNum));
		
		//System.out.println("rfefiejrf "+ gw3[0]);
		for(int i = 0; i<4; i++) {
			w4[i] = Integer.toHexString(Integer.parseInt(w0[i], 16) ^ Integer.parseInt(gw3[i], 16));
			w5[i] = Integer.toHexString(Integer.parseInt(w4[i], 16) ^ Integer.parseInt(w1[i], 16));
			w6[i] = Integer.toHexString(Integer.parseInt(w5[i], 16) ^ Integer.parseInt(w2[i], 16));
			w7[i] = Integer.toHexString(Integer.parseInt(w6[i], 16) ^ Integer.parseInt(w3[i], 16));
			
		}
		
		
		
		for(int i=0; i<4; i++) {
			key[i] = w4[i];
			key[i+4] = w5[i];
			key[i+8] = w6[i];
			key[i+12] = w7[i];
		}
		
		
		
		return roundkeyCalculator(key, keyNum-1, roundNum+1);
		
		
	}
	
	
	//class for the grunt work of doing steps of AES
	private String convert() {//String plainText, String key) {
		String ciphertext = "";
		//Holds split strings as separate characters
		char[] charKey = key.toCharArray();
		char[] charPt = plainText.toCharArray();
		
		//Holds the hex value for each character
		String[] hexKey = new String[charKey.length]; 
		String[] hexPlain = new String[charKey.length]; 
		
		for(int i=0; i<charKey.length; i++) {
			hexKey[i] = Integer.toHexString(charKey[i]);
			hexPlain[i] = Integer.toHexString(charPt[i]);
		}
		/*
		for(String i:hexKey) {
			System.out.println(i);
		}
		for(String j:hexPlain) {
			System.out.println(j);
		}
		*/
		//First step is to xor the State Matrix [hexPlain] against the cipher key [hexKey]
		//Both are 4 by 4 matrices, with column dominance
		
		//System.out.println(Integer.toBinaryString(Integer.parseInt("4B", 16)));
		//System.out.println(69 ^ Integer.parseInt("4B", 16));
		//System.out.println(0x69 ^ 0x4B);
		//System.out.println(Integer.toHexString(0x69 ^ 0x4B));
		//System.out.println(Integer.toHexString((byte)hexKey[10] ^ (byte)hexPlain[10]));
		//String hex = String.format("0x%02X", (int) charKey[9]);
		
		//byte bytes[] = new byte[hexKey.length];
		//bytes[9] = (byte)charPt[9];


		//System.out.println(Integer.toHexString(Integer.parseInt(hexKey[9], 16) ^ Integer.parseInt(hexPlain[9],16)));
		//System.out.println(bytes[9]);
		
		//System.out.println();
		
		/*
		 * String[] addedRoundkey = xor(hexKey, hexPlain);
		for(String j:addedRoundkey) {
			System.out.println(j);
		}
		System.out.println();

				
		String[] sb = sBox(addedRoundkey);
		System.out.println();
		for(String j:sb) {
			System.out.println((j));
		}
		
		
		String[] sr = shiftRow(sb);
		System.out.println();
		for(String j:sr) {
			System.out.println((j));
		}
		
		String[] mc = mixCol(sr);
		System.out.println();
		for(String j:mc) {
			System.out.println((j));
		}
		
		System.out.println();
		  
		 String[] g = (roundkeyCalculator(hexKey, 1, 1));
		for(String j:g) {
			System.out.println((j));
		}
		
		System.out.println();

		String[] lststp = xor(mc, g);
		for(String j:lststp) {
			System.out.println((j));
		}
		 */
		
		//System.out.println(Integer.toHexString(0xB7 ^ 0x01));
		//System.out.println(Integer.toHexString(Integer.parseInt("E2", 16) ^ 0x73));
		//System.out.println();
		//System.out.println(Integer.parseInt("10", 16) ^ 0x1B);
		int len = hexPlain.length;
		
		
		String[] mc = new String[len];
		String[] g = new String[len];
		
		for(int i= 0; i<hexPlain.length; i++) {
			mc[i] = hexPlain[i];
			g[i] = hexKey[i];
		}
		
		String[] addedRoundkey = new String[len], sb = new String[len], 
				sr = new String[len], lststp = new String[len];
		addedRoundkey = xor(g, mc);
		
		for(int i = 0; i<10; i++) {
			
			sb = sBox(addedRoundkey);
			sr = shiftRow(sb);
			if(i==9) {
				g = (roundkeyCalculator(hexKey, i+1, 1));
				addedRoundkey = xor(g, sr);
				break;
			}
			mc = mixCol(sr);
			g = (roundkeyCalculator(hexKey, i+1, 1));
			//lststp = xor(mc, g);
			
			addedRoundkey = xor(g, mc);
		}
		
		
		//addedRoundkey = xor(g, mc);
		
		String digitsFinal = "0123456789abcdef";
		for(String j:addedRoundkey) {
			//System.out.println((j));
			ciphertext += j;
		}
		
		double middleVal = 0;
		int temp;
//		for(int i = 31; i>0; i-=4) {
//			middleVal = 0;
//			for(int j = 0; j<=3; j++) {
//				temp = digitsFinal.indexOf(ciphertext.charAt(i-j));
//				//System.out.println(temp);
//				middleVal += temp*(Math.pow(16, j));
//				//System.out.println(middleVal);
//			}
//			//System.out.println(middleVal);
//			token += middleVal;
//		}
		
		for(int i = 0; i<=31; i++) {
			temp = digitsFinal.indexOf(ciphertext.charAt(31-i));
			middleVal += (temp * Math.pow(16, i)) % 1000000;
			//System.out.println(temp + " "+ (temp * Math.pow(16, i))+"  "+(temp * Math.pow(16, i))%1000000);

		}
		//System.out.println((int)middleVal % 1000000);
		
		int tok = (int)middleVal % 1000;
		int firstPart = ((int)middleVal%1000000)/1000;
		String finalToken = String.format("%03d", firstPart)+" "+String.format("%03d", tok);

		//String finalToken = Integer.toString(firstPart)+" "+Integer.toString(tok);
		return finalToken;
	}
	
	
	
	
	
	public static void main(String[] args) {
		//String plainText = "Two One Nine Two";
		//String key = "Thats my Kung Fu";
		String text = args[0];
		String tokenKey = args[1];
		
		//AES aes = new AES(plainText, key);
		tokenKey = convertTokenKey(tokenKey);
		AES aes = new AES(text, tokenKey);
		System.out.print(aes.convert());
		
	}

}
