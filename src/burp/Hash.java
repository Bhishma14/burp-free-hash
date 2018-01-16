/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;

/**
 *
 * @author RAMMARJ
 */
public class Hash {

    static final String MD5 = "MD5";
    static final String SHA_1 = "SHA-1";
    static final String SHA_224 = "SHA-224";
    static final String SHA_256 = "SHA-384";
    static final String SHA_384 = "SHA-384";
    static final String SHA_512 = "SHA-512";
    private LinkedList<String> hashesAlg;
    private IExtensionHelpers helpers;

    public Hash() {
        this.helpers = helpers;
        hashesAlg = new LinkedList<String>();
        hashesAlg.add(MD5);
        hashesAlg.add(SHA_1);
        hashesAlg.add(SHA_224);
        hashesAlg.add(SHA_256);
        hashesAlg.add(SHA_384);
        hashesAlg.add(SHA_512);
    }
    
    public LinkedList<String> getHashAlgos(){
        return hashesAlg;
    }

    private String hash(String type, String s) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(type);
        return byteArrayToHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
    }

    private String byteArrayToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(String.format("%02x", new Object[]{Integer.valueOf(b & 0xFF)}));
        }
        return builder.toString();
    }

    private LinkedList<String> getParams() {
        LinkedList<String> linkedList = new LinkedList<String>();
        linkedList.add("Joaquin");
        linkedList.add("Ramirez");
        linkedList.add("Martinez");
        linkedList.add("ramirez");
        linkedList.add("martinez");
        linkedList.add("joaquin");
        linkedList.add("Joaquin Ramirez Martinez");
        linkedList.add("Joaquin Ramirez");
        linkedList.add("joaquin.ramirez.mtz.lab@gmail.com");
        linkedList.add("strparser@gmail.com");
        return linkedList;
    }

    public LinkedList<Item> getItems() throws NoSuchAlgorithmException {
        LinkedList<Item> items = new LinkedList<>();
        LinkedList<String> params = getParams();
        LinkedList<String> hashesAlgs = getHashesAlg();
        for (String param : params) {
            for (String hashAlg : hashesAlgs) {
                Item item = new Item();
                item.setName(param);
                item.setHash(hashAlg);
                item.setValue(hash(hashAlg, param));
                items.add(item);
            }
        }
        return items;
    }

    public LinkedList<String> getHashesAlg() {
        return hashesAlg;
    }

}
