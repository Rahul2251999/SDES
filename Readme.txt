1.	I've had included SDES.java file, which implements S-DES, below.

2.	Key1 : 1100000111
	Key2 : 1010110101
	
	20-bit key --> 11001111110101010011


To run the packed sdes.jar from terminal
java -jar sdes.jar


Output of the code in terminal:

-----Meet in the middle-----
[11001111110101010011]
-----35ms
-----Brute Force-----
[11001111110101010011]
5242880iterations for bruteforce
-----2623ms
-----Cipher Block Chaining-----
Congratulations on your success!
-----Weak keys-----
[0000000000, 1000010111, 1111111111, 0111101000]