LTVIP2024TMID13132---SmartInternz-Long-Term-Internship-
This project is for the fullfillment of the Long-Term Internship &amp; Final Project of a contributors. This project is entitled as SHL: A Secure Homomorphic Lightweight Cryptography Algorithm for IoT.  
The main idea of this project is taken from our observation that there were many Lightweight Cryptography Algorithms for IoT but very few of them were using the resources of the IoT effectively. So, Under this project, A Secure Homomorphic Lightweight Cryptography Algorithm for secure communication in IoT. 
In this project, a new Lightweight Cryptography algorithm makes use of resources effectively and increases the performance of the system and better security too. 
Plaintext is nothing but, the input given by the user or the input that is to convert to the ciphertext. This project has restricted the size of the input of the Lightweight Cryptographic Algorithm (LWC) because of resource constraints. The proposed algorithm will take the input of 128 – bits, the input which was given by the user can be of any length but the input block size of the SHL is 128 – bits. If the size of the input is less than 128 then apply padding for the input to full fill the block up to its mark. After the selection of the plaintext which was to be encrypted, now the algorithm will arrange that plaintext into a block which has the size of 8 rows and 16 columns (8*16) matrix. The plaintext is to be fitted from the Top to Bottom method for a single column at a time. 
Round Operations are the operations that were performed on the plaintext to convert them into unreadable text which is also known as Ciphertext or Encrypted Text. The Round operations to be performed in SHL are:
Permutation Box
Substitution Box
Transformations 
Function Box
Permutation Box
Permutation Box is well known for the interchange of the positions of the bits in the matrix. This Project has adapted the Algorithm Specific Permutation. So, under this permutation, this project  perform three operations which are known as:
Shift Up: Under this operation, we rotate the matrix in the direction of Up.
Shift Left: After performing Shift Up on a matrix, now we perform Shift Left on the resultant matrix of the Shift Up. Under Shift Left the rotation of the matrix is performed in the direction of Left.
Shift Up: This Shift Up operation is the same as the above one, which performs a rotation operation on the matrix in the upward direction.
This Permutation operation is performed at the start and ends in the Round operation
Substitution Box, this box will help us to generate confusion between the bits. Under this project, this project has adapted the Customized S-Box which was defined by the Vendor of the Algorithm. The Working of this S-Box was: First we will extract 4 bits from the 8*16  matrix, those 4 bits should be of the same column. After extraction, we concat those 4 bits and look them up on the S-Box for substitution. Here the main important thing is this project uses 2 S-Boxes one is for Encryption and another one is for Decryption. The algorithm will look for the S-Box with the corresponding operation.

Transformation, Under this total project Transformation is the simple operation to be performed. It simply converts the 1’s and 0’s to 0’s and 1’s 
Function Box, Function is the crucial step for this entire project. Function Box takes the input of the 8*16 matrix and performs XOR operation with the Key. The key was of the same length as the text. After performing XOR we will perform the Transformation operation which was mentioned above as it was the same. 

The last operation for the Round was Permutation, This was the same as the above one.
Key Management: The Key being used, is of a predefined function named KDF (Key Derivative Function) for inferring the key. KDF uses a few parameters like Secret Message, Salt, and Number of Iterations. Algorithm Specific parameters, Size of the Output key, and Number of Keys to be derived.  All these fields are well-known to every user so this project has a restricted few parameters and liberated few parameters like Secret Message, Salt. These are the selected and given by the user so that both users. This KDF is a one-way function that can’t be decrypted. 








