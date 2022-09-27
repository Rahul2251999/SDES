package com.networksecurity;

/*
 * This program implements S-DES (4 rounds) and Double S-DES and uses it to demonstrate meet in the middle attack
 * to determine the 20 bit key bundle in ECB mode. It demonstrates the difference between the time taken to 
 * determine the key using meet in the middle attack and brute force.
 * It also implements Double S-DES in Cipher Block Chaining mode to decrypt the cipher text
 * It alse finds the list of S-DES Weak keys
 * 
 * @author C.SIDDHARTH
 * 
 */
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

import org.apache.commons.collections.map.MultiValueMap;

public class SDES {

	static int key[] = new int[10];				//The 10-bit Key
	static int nkeys[][] = new int[4][8];		//Generated 8-bit Keys 

	//Primitive Functions S1 and S2
	final static int[][] S1 = { {1,0,3,2} , {3,2,1,0} , {0,2,1,3} , {3,1,3,2} } ;
	final static int[][] S2 = { {0,1,2,3},  {2,0,1,3}, {3,0,1,0}, {2,1,0,3}} ;


//*************************************************************************************************************************************************
//	Functions Related to Key Generation - Begin
//*************************************************************************************************************************************************

	//Converts the key from string and initializes the 10-bit key
	private static void assignkey(String ipkey) 
	{
		for(int i=0;i<ipkey.length();i++)
			key[i] = Integer.parseInt(Character.toString(ipkey.charAt(i)));
	}

	//Initializes the 10-bit key
	private static void assignkey(int[] ipkey) 
	{
		key = ipkey;
	}

	//Generates 4 8-bit keys from the 10-bit key 
	private static void generateKeys() 
	{
		int pc1_key[] = permutedChoice1(key);		//permuted Choice 1 is Computed
		int c[] = new int[5];
		int d[] = new int[5];

		for(int i=0;i<5;i++)						//Split into left and right blocks C & D
		{
			c[i]=pc1_key[i];
			d[i]=pc1_key[i+5];
		}

		c = leftshift(c,1);						//Performs Left shift
		d = leftshift(d,1);

		nkeys[0] = permutedChoice2(c,d);		//permuted Choice 2 is Computed to generate K1

		//Left shift operations and Permuted Choice 2 is Computed to generate K2,K3 & K4

		for(int i=1;i<=3;i++)
		{
			c = leftshift(c, 2);
			d = leftshift(d, 2);

			nkeys[i] = permutedChoice2(c,d);	
		}

	}


	//Computes the Permutation choice 2
	private static int[] permutedChoice2(int[] c, int[] d) 
	{

		int[] pc2key = new int[8];

		pc2key[0] = d[0];
		pc2key[1] = c[2];
		pc2key[2] = d[1];
		pc2key[3] = c[3];
		pc2key[4] = d[2];
		pc2key[5] = c[4];
		pc2key[6] = d[4];
		pc2key[7] = d[3];

		return pc2key;		
	}

	//Left shifts the element C by shiftby bits
	private static int[] leftshift(int[] c, int shiftby) 
	{

		int len = c.length;

		int[] temp = new int[len];

		for(int i=shiftby,j=0;j<len;i++,j++)
			temp[j]=c[i%len];

		return temp;

	}


	//Computes the Permutation choice 1
	private static int[] permutedChoice1(int[] key) 
	{

		int[] pc1key = new int[10];

		pc1key[0] = key[2];
		pc1key[1] = key[4];
		pc1key[2] = key[1];
		pc1key[3] = key[6];
		pc1key[4] = key[3];
		pc1key[5] = key[9];
		pc1key[6] = key[0];
		pc1key[7] = key[8];
		pc1key[8] = key[7];
		pc1key[9] = key[5];

		return pc1key;		
	}




//----------------------------------------Functions Related to Key Generation - End --------------------------------------------------------------



//*************************************************************************************************************************************************
//		Functions Related to S-DES Encryption/Decryption - Begin
//*************************************************************************************************************************************************

	//Converts String to integer array for processing
	private static int[] convertpt(String plaintext) 
	{
		int pt[] = new int[plaintext.length()];
		for(int i=0;i<plaintext.length();i++)
			pt[i] = Integer.parseInt(Character.toString(plaintext.charAt(i)));
		return pt;
	}


	//Encrypts the plain text to cipher text
	private static int[] encrypt(int[] plaintext) {

		int iptext[] = initialpermutation(plaintext);		//Initial Permutation is applied on the 8-bit plain text
		int l[] = new int[4];
		int r[] = new int[4];
		int fx[] = new int[4];
		int swap[] = new int[4];
		int ciphertext[] = new int[8];

		for(int i=0;i<4;i++)								//Split into left and right blocks L & R
		{
			l[i]=iptext[i];
			r[i]=iptext[i+4];
		}


		for(int k =0;k<4;k++)
		{
			fx = cipherFunction(r,k);				//Cipher function f is computed by using key in order K1 to K4

			for (int i=0;i<4;i++)
				l[i]=l[i] ^ fx[i];					//L is XOR with f(x)

			if(k==3)
				break;
			swap = l;								//L and R blocks are swapped 
			l = r;
			r = swap;
		}


		ciphertext = invpermute(l,r);				//Inverse Initial Permutation is applied to produce the cipher text

		return ciphertext;

	}


	//Decrypts the cipher text to plain text
	private static int[] decrypt(int[] plaintext) {

		int iptext[] = initialpermutation(plaintext);	//Initial Permutation is applied on the 8-bit cipher text
		int l[] = new int[4];
		int r[] = new int[4];
		int fx[] = new int[4];
		int swap[] = new int[4];
		int ciphertext[] = new int[8];

		for(int i=0;i<4;i++)							//Split into left and right blocks L & R
		{
			l[i]=iptext[i];
			r[i]=iptext[i+4];
		}


		for(int k =0;k<4;k++)
		{
			fx = cipherFunction(r,3-k);					//Cipher function f is computed by using key in the reverse order 4 to 1

			for (int i=0;i<4;i++)
				l[i]=l[i] ^ fx[i];						//L is XOR with f(x)

			if(k==3)
				break;
			swap = l;									//L and R blocks are swapped 
			l = r;
			r = swap;
		}


		ciphertext = invpermute(l,r);					//Inverse Initial Permutation is applied to produce the plain text

		return ciphertext;

	}

	//Performs the Inverse Initial Permutation
	private static int[] invpermute(int[] l, int[] r) {

		int[] op = new int[8];

		op[0] = l[3];
		op[1] = l[0];
		op[2] = l[2];
		op[3] = r[0];
		op[4] = r[2];
		op[5] = l[1];
		op[6] = r[3];
		op[7] = r[1];

		return op;		
	}

	//Calculates the Cipher Function Fx
	private static int[] cipherFunction(int[] r,int key) 
	{
		int ebitper[] = new int[8];
		int xor[] = new int[8];

		ebitper = exppermutation(r);							//E-bit Selection table is used to convert 4-bit to 8bit

		for(int i=0;i<8;i++)
			xor[i] = ebitper[i] ^ nkeys[key][i];							//E is XOR with Key k

		//Selection Functions S1 and S2 are computed

		int op_s1[] = getbinary(S1[xor[0]*2+xor[3]][xor[1]*2+xor[2]]);
		int op_s2[] = getbinary(S2[xor[4]*2+xor[7]][xor[5]*2+xor[6]]);

		int perm4[] = permute4(op_s1,op_s2);					//Permutation function is called to yield 4 bit output

		return perm4;


	}

	//Calculates the permutation to yield 4-bit output which is used in the cipher function 
	private static int[] permute4(int[] op_s1, int[] op_s2) 
	{

		int[] perm4 = new int[4];

		perm4[0] = op_s1[1];
		perm4[1] = op_s2[1];
		perm4[2] = op_s2[0];
		perm4[3] = op_s1[0];

		return perm4;	

	}


	//Converts integer to binary
	private static int[] getbinary(int i) {

		int temp[] = new int[2];

		temp[1] = i & 1;
		temp[0] = ((i & (1<<1)) != 0)?1:0;

		return temp;


	}

	//Computes E-bit Selection
	private static int[] exppermutation(int[] r) 
	{
		int[] temp = new int[8];

		temp[0]  = r[3];
		temp[1]  = r[0];
		temp[2]  = r[1];
		temp[3]  = r[2];
		temp[4]  = r[1];
		temp[5]  = r[2];
		temp[6]  = r[3];
		temp[7]  = r[0];

		return temp;
	}

	//Computes the initial permutation
	private static int[] initialpermutation(int[] plaintext) 
	{

		int[] ip = new int[8];

		ip[0] = plaintext[1];
		ip[1] = plaintext[5];
		ip[2] = plaintext[2];
		ip[3] = plaintext[0];
		ip[4] = plaintext[3];
		ip[5] = plaintext[7];
		ip[6] = plaintext[4];
		ip[7] = plaintext[6];

		return ip;		
	}

	//To check if input is valid bit input
	private static boolean check_valid_ip(String ipkey, int nobits) 
	{

		if(ipkey.length() == nobits)
		{
			for(int i=0;i<nobits;i++)
				if(!(ipkey.charAt(i) == '0' || ipkey.charAt(i) == '1'))
					return false;
		}
		else
			return false;
		return true;
	}

//----------------------------------------Functions Related to S-DES Encryption/Decryption - End ------------------------------------------------------------

	/* 
	 * The primary function carries out five operations Manual Mode: Allows user to encrypt plain text with an 8-bit key using a 10-bit key. Using known plain/cipher text pairings in Double S-DES employed in ECB mode, it illustrates a meet-in-the-middle attack; it also displays a brute-force attack; and it demonstrates CBC by decrypting the cipher text in Cipher Block Chaining mode. Find weak keys: It lists the S-DES weak keys. The S-DES is tested against the S-DES Known Answer Test in the auto test mode.

	 */
	public static void main(String[] args) {


		String ipkey,iplaintext,ciphertext;
		boolean ipflag = false;
		long startTime,endTime;

		Scanner sc = new Scanner(System.in);

		boolean autotestmode = false;
		boolean meetinthemiddle = true;
		boolean bruteforce = true;
		boolean manualmode = false;
		boolean CBCMode = true;
		boolean findweakkeys = true;
		if(meetinthemiddle)
		{

			System.out.println("-----Meet in the middle-----");
			startTime = System.currentTimeMillis();
			meetinthemiddle();
			endTime = System.currentTimeMillis();
			System.out.println("-----"+(endTime-startTime)+"ms");

		}

		//Calls and times the bruteforce attack to determine the keys
		if(bruteforce)
		{
			System.out.println("-----Brute Force-----");
			startTime = System.currentTimeMillis();
			bruteforce();
			endTime = System.currentTimeMillis();
			System.out.println("-----"+(endTime-startTime)+"ms");
		}

		/* Manual Mode
		 * Input : 	8-bit  Plain text
		 * 			10-bit Key
		 * 
		 * Output:	8-bit  Cipher text
		 */
		if(manualmode)
		{
			do
			{
				if(ipflag)
					System.out.println("Invalid input\nEnter a valid 8 bit Plain Text:\t");
				else
					System.out.println("Enter the 8 bit Plain Text:\t");

				iplaintext = sc.nextLine();
				ipflag = true;
			}while(!check_valid_ip(iplaintext,8));

			ipflag = false;

			do
			{
				if(ipflag)
					System.out.println("Invalid input\nEnter a valid 10 bit Key:\t");
				else
					System.out.println("Enter the 10 bit Key:\t");

				ipkey = sc.nextLine();
				ipflag = true;
			}while(!check_valid_ip(ipkey,10));


			assignkey(ipkey);
			generateKeys();

			int plaintext[] = convertpt(iplaintext);
			ciphertext =  Arrays.toString(encrypt(plaintext));


			System.out.println("ciphertext :\t"+ciphertext);
		}


		//Used to test the S-DES against the S-DES Known Answer Test
		if(autotestmode)
		{
			String test_key = "0000000000";
			String test_plaintext = "00000001";
			int[] testct = new int[8];
			int[] testpt = new int[8];

			System.out.println("\n\t\t\tPlaintext\t\t\t\t\tKey\t\t\t\tCipherText\n");

			assignkey(test_key);
			generateKeys();


			int testtext[] = convertpt(test_plaintext);

			for(int c=1;c<=8;c++)
			{

				testct =  encrypt(testtext);
				testpt = decrypt(testct);

				System.out.println("\t\t"+Arrays.toString(testtext)+"\t\t"+Arrays.toString(key)+"\t\t"+Arrays.toString(testct));

				testtext = leftshift(testtext, 1);

			}

			test_key = "0000000001";
			test_plaintext = "00000000";
			testtext = convertpt(test_plaintext);
			int testkeys[] = convertpt(test_key);
			System.out.println("\n\n");
			for(int c=1;c<=10;c++)
			{

				assignkey(testkeys);
				generateKeys();
				ciphertext =  Arrays.toString(encrypt(testtext));

				System.out.println("\t\t"+Arrays.toString(testtext)+"\t\t"+Arrays.toString(key)+"\t\t"+ciphertext);

				testkeys = leftshift(testkeys, 1);

			}


			System.out.println("\n\n");


			assignkey("0000000011");
			generateKeys();
			ciphertext =  Arrays.toString(encrypt(testtext));
			System.out.println("\t\t"+Arrays.toString(testtext)+"\t\t"+Arrays.toString(key)+"\t\t"+ciphertext);

			assignkey("0011001010");
			generateKeys();
			ciphertext =  Arrays.toString(encrypt(testtext));
			System.out.println("\t\t"+Arrays.toString(testtext)+"\t\t"+Arrays.toString(key)+"\t\t"+ciphertext);

			assignkey("0001011001");
			generateKeys();
			ciphertext =  Arrays.toString(encrypt(testtext));
			System.out.println("\t\t"+Arrays.toString(testtext)+"\t\t"+Arrays.toString(key)+"\t\t"+ciphertext);

			assignkey("1011001111");
			generateKeys();
			ciphertext =  Arrays.toString(encrypt(testtext));
			System.out.println("\t\t"+Arrays.toString(testtext)+"\t\t"+Arrays.toString(key)+"\t\t"+ciphertext);

		}

		if(CBCMode)
		{
			System.out.println("-----Cipher Block Chaining-----");
			CBCMode();		//Invokes Cipher Block Chaining
		}

		if(findweakkeys)
			{
			System.out.println("-----Weak keys-----");
			findweakkeys();		//Invokes find weak keys
			}

	}


	//Finds All the S-DES weak keys 
	private static void findweakkeys() 
	{
		String ttkey;

		Set<String> weak_set = new HashSet<String>();

		for(int j=0;j<1024;j++)
		{

			ttkey = String.format("%10s", Integer.toBinaryString(j)).replace(' ', '0');		//Generates all 10-bit keys

			assignkey(ttkey);																//Key is assigned and subkeys are generated
			generateKeys();

			//if sub keys match then it is a weak key
			if(Arrays.equals(nkeys[0],nkeys[1]) && Arrays.equals(nkeys[0],nkeys[2]) && Arrays.equals(nkeys[0],nkeys[3]))
				weak_set.add(ttkey);

		}

		System.out.println(weak_set);
	}




	/* Applies all the 2^10 * 2^10 = 2^20 = 1048576 Combination of keys to find the key used in the known plain text/cipher text pairs
	 * As there are total of 5 known pairs the brute force algorithm runs 5 * 2^20 = 5242880 times to find the key used 
	 */ 
	private static void bruteforce() 
	{
		//Known plain text/cipher text pairs
		String plaintext[] = {"0x42","0x72","0x75","0x74","0x65"};
		String ciphertext[] = {"0x52", "0xf0", "0xbe", "0x69", "0x8a"};
		String temp,ttkey1,ttkey2;

		int ptext[][] = new int[plaintext.length][8];
		int ctext[][] = new int[ciphertext.length][8];

		Set<String> key1_key2_set = new HashSet<String>();

		long loopcount = 0;

		for (int i=0;i<plaintext.length;i++)
		{

			Set<String> temp_key1_key2_set = new HashSet<String>();

			//Plain text and cipher text are converted to binary from hex

			temp = String.format("%8s", Integer.toBinaryString(Integer.parseInt(plaintext[i].replaceFirst("0x", ""), 16))).replace(' ', '0');

			ptext[i] = convertpt(temp);

			temp = String.format("%8s", Integer.toBinaryString(Integer.parseInt(ciphertext[i].replaceFirst("0x", ""), 16))).replace(' ', '0');

			ctext[i] = convertpt(temp);


			//Generates all combination of 20 bit key bundle and encrypts the plain text to cipher text 
			for(int j=0;j<1024;j++)
			{

				ttkey1 = String.format("%10s", Integer.toBinaryString(j)).replace(' ', '0');

				assignkey(ttkey1);
				generateKeys();
				int intermediate[] = encrypt(ptext[i]);			//1st encryption

				for(int k=0;k<1024;k++)	
				{
					//This runs total of 2^20 times

					ttkey2 = String.format("%10s", Integer.toBinaryString(k)).replace(' ', '0');

					assignkey(ttkey2);
					generateKeys();
					int []ciperttext = encrypt(intermediate);	//2nd encryption

					if(Arrays.equals(ciperttext, ctext[i]))		//Checks for match
						temp_key1_key2_set.add(ttkey1+ttkey2);
					loopcount++;
				}
			}

			if(i==0)
				key1_key2_set.addAll(temp_key1_key2_set);
			else
				key1_key2_set.retainAll(temp_key1_key2_set);		// Computing the Common keys in all the 5 known plain/cipher text pairs to get the final key
		}
		System.out.println(key1_key2_set);		//Final Key used to encrypt
		System.out.println(loopcount+"iterations for bruteforce");			// Total number of times the innermost loop ran 
	}


	/* This function implements meet in the middle attack by encrypting the plain text and decrypting the cipher text to produce
	 * a intemediate text and then it matches for the intermediate text.
	 * Thus this runs max of 2^10 + 2^10 = 2^11 times to find the keys 
	 */
	private static void meetinthemiddle() 
	{
		String plaintext[] = {"0x42","0x72","0x75","0x74","0x65"};
		String ciphertext[] = {"0x52", "0xf0", "0xbe", "0x69", "0x8a"};
		String temp,ttkey;

		int ptext[][] = new int[plaintext.length][8];
		int ctext[][] = new int[ciphertext.length][8];

		Set<String> key1_key2_set = new HashSet<String>();

		for (int i=0;i<plaintext.length;i++)
		{

			Set<String> temp_key1_key2_set = new HashSet<String>();

			MultiValueMap int_ct_keys1 = new MultiValueMap();
			MultiValueMap int_ct_keys2 = new MultiValueMap();

			//Plain text and cipher text are converted to binary from hex
			temp = String.format("%8s", Integer.toBinaryString(Integer.parseInt(plaintext[i].replaceFirst("0x", ""), 16))).replace(' ', '0');

			ptext[i] = convertpt(temp);

			temp = String.format("%8s", Integer.toBinaryString(Integer.parseInt(ciphertext[i].replaceFirst("0x", ""), 16))).replace(' ', '0');

			ctext[i] = convertpt(temp);

			if(i==0)
			{	
				//Trying All Combination of 2^10 Keys to generate the intermediate cipher text
				for(int j=0;j<1024;j++)
				{

					ttkey = String.format("%10s", Integer.toBinaryString(j)).replace(' ', '0');

					assignkey(ttkey);
					generateKeys();
					String intermediate = Arrays.toString(encrypt(ptext[i]));

					int_ct_keys1.put(intermediate, ttkey);

					intermediate = Arrays.toString(decrypt(ctext[i]));

					int_ct_keys2.put(intermediate, ttkey);

				}

				Set<String> intcipertexts = int_ct_keys1.keySet();

				//Finding a match in the intermediate cipher text to find the keys
				for (String intcipertext : intcipertexts) 
				{

					if(int_ct_keys2.containsKey(intcipertext))
					{
						List<String> keylist1 = (List<String>) int_ct_keys1.get(intcipertext);
						List<String> keylist2 = (List<String>) int_ct_keys2.get(intcipertext);

						for(String k1 : keylist1)
							for(String k2 : keylist2)
								temp_key1_key2_set.add(k1+"|"+k2);		
					}

				}

				key1_key2_set.addAll(temp_key1_key2_set);

			}
			else
			{
				//Iterating the set of all possible keys instead of all keys to reduce the iterations further
				for(String reducedkeys : key1_key2_set)
				{
					String keys[]= reducedkeys.split("\\|");

					assignkey(keys[0]);
					generateKeys();
					String intermediate1 = Arrays.toString(encrypt(ptext[i]));

					assignkey(keys[1]);
					generateKeys();
					String intermediate2 = Arrays.toString(decrypt(ctext[i]));

					if(intermediate1.equals(intermediate2))
						temp_key1_key2_set.add(keys[0]+"|"+keys[1]);

				}

				key1_key2_set.retainAll(temp_key1_key2_set);		// Computing the Common keys in all the 5 known plain/cipher text pairs to get the final key
			}
		}
		System.out.println(key1_key2_set.toString().replaceAll("\\|", ""));
	}


	//In this S-DES is implemented in Cipher Block Chaining mode to decrypt the cipher text using the key found by the meet in the middle attack
	private static void CBCMode() 
	{
		String ivtext = "0x9c";
		String ciphertext = "0x586519b031aaee9a235247601fb37baefbcd54d8c3763f8523d2a1315ed8bdcc";
		String cbckey1 = "1100000111";
		String cbckey2 = "1010110101";
		String plaintext ="";

		int ivt[] = new int[8];
		int intermediate[] = new int[8];

		ciphertext = ciphertext.replaceFirst("0x", "");
		int clength = ciphertext.length()/2; 

		int ctext[][] = new int [clength][8];
		int ptext[][] = new int [clength][8];

		String temp ;

		//cipher text is converted to binary from hex

		temp = String.format("%8s", Integer.toBinaryString(Integer.parseInt(ivtext.replaceFirst("0x", ""), 16))).replace(' ', '0');

		ivt = convertpt(temp);


		for(int i=0,j=0;i<clength*2;i+=2,j++)
		{
			temp = String.format("%8s", Integer.toBinaryString(Integer.parseInt(ciphertext.substring(i, i+2), 16))).replace(' ', '0');
			ctext[j] = convertpt(temp);
		}

		int key1[] = convertpt(cbckey1) ,key2 [] = convertpt(cbckey2);	//keys are assigned

		for(int i=0;i<ctext.length;i++)
		{


			assignkey(key2);
			generateKeys();
			intermediate = decrypt(ctext[i]);	//decrypted using the key2

			assignkey(key1);
			generateKeys();
			ptext[i] = decrypt(intermediate);	//decrypted using the key1

			//The XOR operation with the previous cipher block/Initialization vector is performed is performed
			if(i==0)
				for(int j=0;j<8;j++)
					ptext[i][j] = ivt[j] ^ ptext[i][j];		
			else
				for(int j=0;j<8;j++)
					ptext[i][j] = ctext[i-1][j] ^ ptext[i][j];

			//The final Plain text
			plaintext += new Character((char)Integer.parseInt(Arrays.toString(ptext[i]).replaceAll("\\[|\\]|,|\\s", ""),2)).toString(); 
		}
		System.out.println(plaintext);
	}

}
