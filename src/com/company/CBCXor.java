package com.company;

import java.io.BufferedReader;
import java.io.FileReader;

import javax.xml.bind.DatatypeConverter;

public class CBCXor {

    public static void main(String[] args) {
        String filename = "input.txt";
        byte[] first_block = null;
        byte[] encrypted = null;
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            first_block = br.readLine().getBytes();
            encrypted = DatatypeConverter.parseHexBinary(br.readLine());
            br.close();
        } catch (Exception err) {
            System.err.println("Error handling file.");
            err.printStackTrace();
            System.exit(1);
        }
        String m = recoverMessage(first_block, encrypted);
        System.out.println("Recovered message: " + m);
    }

    /**
     * Recover the encrypted message (CBC encrypted with XOR, block size = 12).
     *
     * @param first_block
     *            We know that this is the value of the first block of plain
     *            text.
     * @param encrypted
     *            The encrypted text, of the form IV | C0 | C1 | ... where each
     *            block is 12 bytes long.
     */
    private static String recoverMessage(byte[] first_block, byte[] encrypted) {
        //first we need to find the key K, K = C_1 ^ M_1 ^ C_0, where M_1 = first_block and C_0 = IV
        //since key K = C1 + C0 + M1, the length of key = 12 bytes
        //Therefore, we create an array of the length 12
        byte[] keys = new byte [12];

        //fill the array keys with the respective keys
        for (int i = 0; i<12; i++){
            byte res1 = (byte)(encrypted[i]^encrypted[i+12]);//res1 = C0 + C1
            keys[i] = (byte) (res1^first_block[i]);//K=res1 + M1 = C1 + C0 + M1
        }

        //now we know the key stored in keys[]
        //we can recover the message Mi = Ci + C(i-1) + K

        //we get the number of blocks in encrypted[] without the first blcok of IV
        int nbrBlocks = encrypted.length - 12;

        //we create an array message[] which will contain the recovered message and have the length nbrBlocks
        byte[] message = new byte [nbrBlocks];

        //fill the first block of message[] with the known value from first_block[]
        for (int i = 0; i<12; i++){
            message[i] = first_block[i];
        }

        //we fill the remaining part of array with the massage value starting filling the massage[] form index 12
        //since the first block of message is already known and filled

        for (int i = 24; i<encrypted.length; i++){
            byte res1 = (byte)(encrypted[i]^encrypted[i-12]);//res1 = Ci + C(i-1)
            message[i-12] = (byte) (res1^keys[i%12]);//res1 + K = Ci + C(i-1) + K
        }

        return new String(message);

    }
}