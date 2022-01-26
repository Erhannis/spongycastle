package org.spongycastle.crypto.test;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SM3Digest;
import org.spongycastle.util.encoders.Hex;

/**
 * standard vector test for SM3 digest from chinese specification
 */
public class SM3DigestTest
    extends DigestTest
{
    private static String[] messages = {
        // Standard test vectors
        "abc",
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        // Non-standard test vectors
        "",
        "a",
        "abcdefghijklmnopqrstuvwxyz",
    };

    private static String[] hexMessages = {
        /* 2 p.57 ZA */
        "0090" +
        "414C494345313233405941484F4F2E434F4D" +
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498" +
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A" +
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D" +
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2" +
        "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A" +
        "7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857",
        /* 3 p.59 ZA */
        "0090" +
        "414C494345313233405941484F4F2E434F4D" +
        "000000000000000000000000000000000000000000000000000000000000000000" +
        "00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B" +
        "00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD" +
        "013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E" +
        "0165961645281A8626607B917F657D7E9382F1EA5CD931F40F6627F357542653B2" +
        "01686522130D590FB8DE635D8FCA715CC6BF3D05BEF3F75DA5D543454448166612",
        /* 4 p.72 ZA */
        "0090" +
        "414C494345313233405941484F4F2E434F4D" +
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498" +
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A" +
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D" +
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2" +
        "3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655" +
        "3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B",
        /* 5 p.72 ZB */
        "0088" +
        "42494C4C343536405941484F4F2E434F4D" +
        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498" +
        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A" +
        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D" +
        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2" +
        "245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F43" +
        "53C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C",
        /* 6 p.75 ZA */
        "0090" +
        "414C494345313233405941484F4F2E434F4D" +
        "000000000000000000000000000000000000000000000000000000000000000000" +
        "00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B" +
        "00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD" +
        "013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E" +
        "008E3BDB2E11F9193388F1F901CCC857BF49CFC065FB38B9069CAAE6D5AFC3592F" +
        "004555122AAC0075F42E0A8BBD2C0665C789120DF19D77B4E3EE4712F598040415",
        /* 7 p.76 ZB */
        "0088" +
        "42494C4C343536405941484F4F2E434F4D" +
        "000000000000000000000000000000000000000000000000000000000000000000" +
        "00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B" +
        "00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD" +
        "013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E" +
        "0034297DD83AB14D5B393B6712F32B2F2E938D4690B095424B89DA880C52D4A7D9" +
        "0199BBF11AC95A0EA34BBD00CA50B93EC24ACB68335D20BA5DCFE3B33BDBD2B62D",
        /* 8 TopsecCA cert ZA */
        "0080" +
        "31323334353637383132333435363738" +
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC" +
        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93" +
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7" +
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" +
        "D69C2F1EEC3BFB6B95B30C28085C77B125D77A9C39525D8190768F37D6B205B5" +
        "89DCD316BBE7D89A9DC21917F17799E698531F5E6E3E10BD31370B259C3F81C3",
        /* 9 */
        "4D38D2958CA7FD2CFAE3AF04486959CF92C8EF48E8B83A05C112E739D5F181D0" +
        "3082020CA003020102020900" +
        "AF28725D98D33143300C06082A811CCF" +
        "550183750500307D310B300906035504" +
        "060C02636E310B300906035504080C02" +
        "626A310B300906035504070C02626A31" +
        "0F300D060355040A0C06746F70736563" +
        "310F300D060355040B0C06746F707365" +
        "633111300F06035504030C08546F7073" +
        "65634341311F301D06092A864886F70D" +
        "0109010C10626A40746F707365632E63" +
        "6F6D2E636E301E170D31323036323430" +
        "37353433395A170D3332303632303037" +
        "353433395A307D310B30090603550406" +
        "0C02636E310B300906035504080C0262" +
        "6A310B300906035504070C02626A310F" +
        "300D060355040A0C06746F7073656331" +
        "0F300D060355040B0C06746F70736563" +
        "3111300F06035504030C08546F707365" +
        "634341311F301D06092A864886F70D01" +
        "09010C10626A40746F707365632E636F" +
        "6D2E636E3059301306072A8648CE3D02" +
        "0106082A811CCF5501822D03420004D6" +
        "9C2F1EEC3BFB6B95B30C28085C77B125" +
        "D77A9C39525D8190768F37D6B205B589" +
        "DCD316BBE7D89A9DC21917F17799E698" +
        "531F5E6E3E10BD31370B259C3F81C3A3" +
        "733071300F0603551D130101FF040530" +
        "030101FF301D0603551D0E041604148E" +
        "5D90347858BAAAD870D8BDFBA6A85E7B" +
        "563B64301F0603551D23041830168014" +
        "8E5D90347858BAAAD870D8BDFBA6A85E" +
        "7B563B64300B0603551D0F0404030201" +
        "06301106096086480186F84201010404" +
        "03020057",
    };
    
    private static String[] digests = {
        // Standard test vectors
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        // Non-standard test vectors
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
        "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88",
        "b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595",
        // Additional vectors for GMSSL
        "F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A",
        "26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5",
        "E4D1D0C3CA4C7F11BC8FF8CB3F4C02A78F108FA098E51A668487240F75E20F31",
        "6B4B6D0E276691BD4A11BF72F4FB501AE309FDACB72FA6CC336E6656119ABD67",
        "329c2f6030cc7e0ca3af6c97b76243ca250338ad3d3dc3a8b322d1cfdf98c2b7", // original appears wrong -> "ECF0080215977B2E5D6D61B98A99442F03E8803DC39E349F8DCA5621A9ACDF2B",
        "557BAD30E183559AEEC3B2256E1C7C11F870D22B165D015ACF9465B09B87B527",
        "4D38D2958CA7FD2CFAE3AF04486959CF92C8EF48E8B83A05C112E739D5F181D0",
        "C3B02E500A8B60B77DEDCF6F4C11BEF8D56E5CDE708C72065654FD7B2167915A",
    };

    final static String sixtyFourKdigest = "97049bdc8f0736bc7300eafa9980aeb9cf00f24f7ec3a8f1f8884954d7655c1d";
    final static String million_a_digest = "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3";

    SM3DigestTest()
    {
        super(new SM3Digest(), messages, digests);
    }

    public void performTest()
    {
        super.performTest();

        SM3Digest dig = new SM3Digest();
        byte[] resBuf = new byte[dig.getDigestSize()];
        
        vectorTest(dig, 10, resBuf, Hex.decode(hexMessages[0]), Hex.decode(digests[messages.length]));
        vectorTest(dig, 11, resBuf, Hex.decode(hexMessages[1]), Hex.decode(digests[messages.length + 1]));
        vectorTest(dig, 12, resBuf, Hex.decode(hexMessages[2]), Hex.decode(digests[messages.length + 2]));
        vectorTest(dig, 13, resBuf, Hex.decode(hexMessages[3]), Hex.decode(digests[messages.length + 3]));
        vectorTest(dig, 14, resBuf, Hex.decode(hexMessages[4]), Hex.decode(digests[messages.length + 4]));
        vectorTest(dig, 15, resBuf, Hex.decode(hexMessages[5]), Hex.decode(digests[messages.length + 5]));
        vectorTest(dig, 16, resBuf, Hex.decode(hexMessages[6]), Hex.decode(digests[messages.length + 6]));
        vectorTest(dig, 17, resBuf, Hex.decode(hexMessages[7]), Hex.decode(digests[messages.length + 7]));

        sixtyFourKTest(sixtyFourKdigest);
        millionATest(million_a_digest);
    }

    private void vectorTest(
        Digest digest,
        int count,
        byte[] resBuf,
        byte[] input,
        byte[] expected)
    {
        digest.update(input, 0, input.length);
        digest.doFinal(resBuf, 0);

        if (!areEqual(resBuf, expected))
        {
            fail("Vector " + count + " failed got " + new String(Hex.encode(resBuf)));
        }
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new SM3Digest((SM3Digest)digest);
    }

    public static void main(String[] args)
    {
        runTest(new SM3DigestTest());
    }
}
