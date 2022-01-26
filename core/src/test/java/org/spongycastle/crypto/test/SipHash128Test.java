package org.spongycastle.crypto.test;

import java.security.SecureRandom;

import org.spongycastle.crypto.macs.SipHash128;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.util.test.SimpleTest;

/*
 * SipHash test values are taken from the output of the C reference implementations:
 * section "const uint8_t vectors_sip128[64][16]" of the output of command ./vectors.
 */
public class SipHash128Test
    extends SimpleTest
{
    private static final int UPDATE_BYTES = 0;
    private static final int UPDATE_FULL = 1;
    private static final int UPDATE_MIX = 2;

    public String getName()
    {
        return "SipHash128";
    }

    public void performTest()
        throws Exception
    {
        performTest_2_4();
        performTest_4_8();
    }

    private void performTest_2_4()
        throws Exception
    {
        /*
         * SipHash test values are taken from the output of the C reference implementations:
         * section "const uint8_t vectors_sip128[64][16]" of the output of command ./vectors.
         */
        int[][] vectors_sip128 = new int[][]{
            {0xa3, 0x81, 0x7f, 0x04, 0xba, 0x25, 0xa8, 0xe6, 0x6d, 0xf6, 0x72, 0x14, 0xc7, 0x55, 0x02, 0x93,},
            {0xda, 0x87, 0xc1, 0xd8, 0x6b, 0x99, 0xaf, 0x44, 0x34, 0x76, 0x59, 0x11, 0x9b, 0x22, 0xfc, 0x45,},
            {0x81, 0x77, 0x22, 0x8d, 0xa4, 0xa4, 0x5d, 0xc7, 0xfc, 0xa3, 0x8b, 0xde, 0xf6, 0x0a, 0xff, 0xe4,},
            {0x9c, 0x70, 0xb6, 0x0c, 0x52, 0x67, 0xa9, 0x4e, 0x5f, 0x33, 0xb6, 0xb0, 0x29, 0x85, 0xed, 0x51,},
            {0xf8, 0x81, 0x64, 0xc1, 0x2d, 0x9c, 0x8f, 0xaf, 0x7d, 0x0f, 0x6e, 0x7c, 0x7b, 0xcd, 0x55, 0x79,},
            {0x13, 0x68, 0x87, 0x59, 0x80, 0x77, 0x6f, 0x88, 0x54, 0x52, 0x7a, 0x07, 0x69, 0x0e, 0x96, 0x27,},
            {0x14, 0xee, 0xca, 0x33, 0x8b, 0x20, 0x86, 0x13, 0x48, 0x5e, 0xa0, 0x30, 0x8f, 0xd7, 0xa1, 0x5e,},
            {0xa1, 0xf1, 0xeb, 0xbe, 0xd8, 0xdb, 0xc1, 0x53, 0xc0, 0xb8, 0x4a, 0xa6, 0x1f, 0xf0, 0x82, 0x39,},
            {0x3b, 0x62, 0xa9, 0xba, 0x62, 0x58, 0xf5, 0x61, 0x0f, 0x83, 0xe2, 0x64, 0xf3, 0x14, 0x97, 0xb4,},
            {0x26, 0x44, 0x99, 0x06, 0x0a, 0xd9, 0xba, 0xab, 0xc4, 0x7f, 0x8b, 0x02, 0xbb, 0x6d, 0x71, 0xed,},
            {0x00, 0x11, 0x0d, 0xc3, 0x78, 0x14, 0x69, 0x56, 0xc9, 0x54, 0x47, 0xd3, 0xf3, 0xd0, 0xfb, 0xba,},
            {0x01, 0x51, 0xc5, 0x68, 0x38, 0x6b, 0x66, 0x77, 0xa2, 0xb4, 0xdc, 0x6f, 0x81, 0xe5, 0xdc, 0x18,},
            {0xd6, 0x26, 0xb2, 0x66, 0x90, 0x5e, 0xf3, 0x58, 0x82, 0x63, 0x4d, 0xf6, 0x85, 0x32, 0xc1, 0x25,},
            {0x98, 0x69, 0xe2, 0x47, 0xe9, 0xc0, 0x8b, 0x10, 0xd0, 0x29, 0x93, 0x4f, 0xc4, 0xb9, 0x52, 0xf7,},
            {0x31, 0xfc, 0xef, 0xac, 0x66, 0xd7, 0xde, 0x9c, 0x7e, 0xc7, 0x48, 0x5f, 0xe4, 0x49, 0x49, 0x02,},
            {0x54, 0x93, 0xe9, 0x99, 0x33, 0xb0, 0xa8, 0x11, 0x7e, 0x08, 0xec, 0x0f, 0x97, 0xcf, 0xc3, 0xd9,},
            {0x6e, 0xe2, 0xa4, 0xca, 0x67, 0xb0, 0x54, 0xbb, 0xfd, 0x33, 0x15, 0xbf, 0x85, 0x23, 0x05, 0x77,},
            {0x47, 0x3d, 0x06, 0xe8, 0x73, 0x8d, 0xb8, 0x98, 0x54, 0xc0, 0x66, 0xc4, 0x7a, 0xe4, 0x77, 0x40,},
            {0xa4, 0x26, 0xe5, 0xe4, 0x23, 0xbf, 0x48, 0x85, 0x29, 0x4d, 0xa4, 0x81, 0xfe, 0xae, 0xf7, 0x23,},
            {0x78, 0x01, 0x77, 0x31, 0xcf, 0x65, 0xfa, 0xb0, 0x74, 0xd5, 0x20, 0x89, 0x52, 0x51, 0x2e, 0xb1,},
            {0x9e, 0x25, 0xfc, 0x83, 0x3f, 0x22, 0x90, 0x73, 0x3e, 0x93, 0x44, 0xa5, 0xe8, 0x38, 0x39, 0xeb,},
            {0x56, 0x8e, 0x49, 0x5a, 0xbe, 0x52, 0x5a, 0x21, 0x8a, 0x22, 0x14, 0xcd, 0x3e, 0x07, 0x1d, 0x12,},
            {0x4a, 0x29, 0xb5, 0x45, 0x52, 0xd1, 0x6b, 0x9a, 0x46, 0x9c, 0x10, 0x52, 0x8e, 0xff, 0x0a, 0xae,},
            {0xc9, 0xd1, 0x84, 0xdd, 0xd5, 0xa9, 0xf5, 0xe0, 0xcf, 0x8c, 0xe2, 0x9a, 0x9a, 0xbf, 0x69, 0x1c,},
            {0x2d, 0xb4, 0x79, 0xae, 0x78, 0xbd, 0x50, 0xd8, 0x88, 0x2a, 0x8a, 0x17, 0x8a, 0x61, 0x32, 0xad,},
            {0x8e, 0xce, 0x5f, 0x04, 0x2d, 0x5e, 0x44, 0x7b, 0x50, 0x51, 0xb9, 0xea, 0xcb, 0x8d, 0x8f, 0x6f,},
            {0x9c, 0x0b, 0x53, 0xb4, 0xb3, 0xc3, 0x07, 0xe8, 0x7e, 0xae, 0xe0, 0x86, 0x78, 0x14, 0x1f, 0x66,},
            {0xab, 0xf2, 0x48, 0xaf, 0x69, 0xa6, 0xea, 0xe4, 0xbf, 0xd3, 0xeb, 0x2f, 0x12, 0x9e, 0xeb, 0x94,},
            {0x06, 0x64, 0xda, 0x16, 0x68, 0x57, 0x4b, 0x88, 0xb9, 0x35, 0xf3, 0x02, 0x73, 0x58, 0xae, 0xf4,},
            {0xaa, 0x4b, 0x9d, 0xc4, 0xbf, 0x33, 0x7d, 0xe9, 0x0c, 0xd4, 0xfd, 0x3c, 0x46, 0x7c, 0x6a, 0xb7,},
            {0xea, 0x5c, 0x7f, 0x47, 0x1f, 0xaf, 0x6b, 0xde, 0x2b, 0x1a, 0xd7, 0xd4, 0x68, 0x6d, 0x22, 0x87,},
            {0x29, 0x39, 0xb0, 0x18, 0x32, 0x23, 0xfa, 0xfc, 0x17, 0x23, 0xde, 0x4f, 0x52, 0xc4, 0x3d, 0x35,},
            {0x7c, 0x39, 0x56, 0xca, 0x5e, 0xea, 0xfc, 0x3e, 0x36, 0x3e, 0x9d, 0x55, 0x65, 0x46, 0xeb, 0x68,},
            {0x77, 0xc6, 0x07, 0x71, 0x46, 0xf0, 0x1c, 0x32, 0xb6, 0xb6, 0x9d, 0x5f, 0x4e, 0xa9, 0xff, 0xcf,},
            {0x37, 0xa6, 0x98, 0x6c, 0xb8, 0x84, 0x7e, 0xdf, 0x09, 0x25, 0xf0, 0xf1, 0x30, 0x9b, 0x54, 0xde,},
            {0xa7, 0x05, 0xf0, 0xe6, 0x9d, 0xa9, 0xa8, 0xf9, 0x07, 0x24, 0x1a, 0x2e, 0x92, 0x3c, 0x8c, 0xc8,},
            {0x3d, 0xc4, 0x7d, 0x1f, 0x29, 0xc4, 0x48, 0x46, 0x1e, 0x9e, 0x76, 0xed, 0x90, 0x4f, 0x67, 0x11,},
            {0x0d, 0x62, 0xbf, 0x01, 0xe6, 0xfc, 0x0e, 0x1a, 0x0d, 0x3c, 0x47, 0x51, 0xc5, 0xd3, 0x69, 0x2b,},
            {0x8c, 0x03, 0x46, 0x8b, 0xca, 0x7c, 0x66, 0x9e, 0xe4, 0xfd, 0x5e, 0x08, 0x4b, 0xbe, 0xe7, 0xb5,},
            {0x52, 0x8a, 0x5b, 0xb9, 0x3b, 0xaf, 0x2c, 0x9c, 0x44, 0x73, 0xcc, 0xe5, 0xd0, 0xd2, 0x2b, 0xd9,},
            {0xdf, 0x6a, 0x30, 0x1e, 0x95, 0xc9, 0x5d, 0xad, 0x97, 0xae, 0x0c, 0xc8, 0xc6, 0x91, 0x3b, 0xd8,},
            {0x80, 0x11, 0x89, 0x90, 0x2c, 0x85, 0x7f, 0x39, 0xe7, 0x35, 0x91, 0x28, 0x5e, 0x70, 0xb6, 0xdb,},
            {0xe6, 0x17, 0x34, 0x6a, 0xc9, 0xc2, 0x31, 0xbb, 0x36, 0x50, 0xae, 0x34, 0xcc, 0xca, 0x0c, 0x5b,},
            {0x27, 0xd9, 0x34, 0x37, 0xef, 0xb7, 0x21, 0xaa, 0x40, 0x18, 0x21, 0xdc, 0xec, 0x5a, 0xdf, 0x89,},
            {0x89, 0x23, 0x7d, 0x9d, 0xed, 0x9c, 0x5e, 0x78, 0xd8, 0xb1, 0xc9, 0xb1, 0x66, 0xcc, 0x73, 0x42,},
            {0x4a, 0x6d, 0x80, 0x91, 0xbf, 0x5e, 0x7d, 0x65, 0x11, 0x89, 0xfa, 0x94, 0xa2, 0x50, 0xb1, 0x4c,},
            {0x0e, 0x33, 0xf9, 0x60, 0x55, 0xe7, 0xae, 0x89, 0x3f, 0xfc, 0x0e, 0x3d, 0xcf, 0x49, 0x29, 0x02,},
            {0xe6, 0x1c, 0x43, 0x2b, 0x72, 0x0b, 0x19, 0xd1, 0x8e, 0xc8, 0xd8, 0x4b, 0xdc, 0x63, 0x15, 0x1b,},
            {0xf7, 0xe5, 0xae, 0xf5, 0x49, 0xf7, 0x82, 0xcf, 0x37, 0x90, 0x55, 0xa6, 0x08, 0x26, 0x9b, 0x16,},
            {0x43, 0x8d, 0x03, 0x0f, 0xd0, 0xb7, 0xa5, 0x4f, 0xa8, 0x37, 0xf2, 0xad, 0x20, 0x1a, 0x64, 0x03,},
            {0xa5, 0x90, 0xd3, 0xee, 0x4f, 0xbf, 0x04, 0xe3, 0x24, 0x7e, 0x0d, 0x27, 0xf2, 0x86, 0x42, 0x3f,},
            {0x5f, 0xe2, 0xc1, 0xa1, 0x72, 0xfe, 0x93, 0xc4, 0xb1, 0x5c, 0xd3, 0x7c, 0xae, 0xf9, 0xf5, 0x38,},
            {0x2c, 0x97, 0x32, 0x5c, 0xbd, 0x06, 0xb3, 0x6e, 0xb2, 0x13, 0x3d, 0xd0, 0x8b, 0x3a, 0x01, 0x7c,},
            {0x92, 0xc8, 0x14, 0x22, 0x7a, 0x6b, 0xca, 0x94, 0x9f, 0xf0, 0x65, 0x9f, 0x00, 0x2a, 0xd3, 0x9e,},
            {0xdc, 0xe8, 0x50, 0x11, 0x0b, 0xd8, 0x32, 0x8c, 0xfb, 0xd5, 0x08, 0x41, 0xd6, 0x91, 0x1d, 0x87,},
            {0x67, 0xf1, 0x49, 0x84, 0xc7, 0xda, 0x79, 0x12, 0x48, 0xe3, 0x2b, 0xb5, 0x92, 0x25, 0x83, 0xda,},
            {0x19, 0x38, 0xf2, 0xcf, 0x72, 0xd5, 0x4e, 0xe9, 0x7e, 0x94, 0x16, 0x6f, 0xa9, 0x1d, 0x2a, 0x36,},
            {0x74, 0x48, 0x1e, 0x96, 0x46, 0xed, 0x49, 0xfe, 0x0f, 0x62, 0x24, 0x30, 0x16, 0x04, 0x69, 0x8e,},
            {0x57, 0xfc, 0xa5, 0xde, 0x98, 0xa9, 0xd6, 0xd8, 0x00, 0x64, 0x38, 0xd0, 0x58, 0x3d, 0x8a, 0x1d,},
            {0x9f, 0xec, 0xde, 0x1c, 0xef, 0xdc, 0x1c, 0xbe, 0xd4, 0x76, 0x36, 0x74, 0xd9, 0x57, 0x53, 0x59,},
            {0xe3, 0x04, 0x0c, 0x00, 0xeb, 0x28, 0xf1, 0x53, 0x66, 0xca, 0x73, 0xcb, 0xd8, 0x72, 0xe7, 0x40,},
            {0x76, 0x97, 0x00, 0x9a, 0x6a, 0x83, 0x1d, 0xfe, 0xcc, 0xa9, 0x1c, 0x59, 0x93, 0x67, 0x0f, 0x7a,},
            {0x58, 0x53, 0x54, 0x23, 0x21, 0xf5, 0x67, 0xa0, 0x05, 0xd5, 0x47, 0xa4, 0xf0, 0x47, 0x59, 0xbd,},
            {0x51, 0x50, 0xd1, 0x77, 0x2f, 0x50, 0x83, 0x4a, 0x50, 0x3e, 0x06, 0x9a, 0x97, 0x3f, 0xbd, 0x7c,},
        };

        performTest(2, 4, vectors_sip128);
    }

    private void performTest_4_8()
        throws Exception
    {
        int[][] vectors_sip128 = new int[][]{
            {0x1f, 0x64, 0xce, 0x58, 0x6d, 0xa9, 0x04, 0xe9, 0xcf, 0xec, 0xe8, 0x54, 0x83, 0xa7, 0x0a, 0x6c,},
            {0x47, 0x34, 0x5d, 0xa8, 0xef, 0x4c, 0x79, 0x47, 0x6a, 0xf2, 0x7c, 0xa7, 0x91, 0xc7, 0xa2, 0x80,},
            {0xe1, 0x49, 0x5f, 0xa3, 0x96, 0xca, 0x2d, 0xc6, 0x22, 0x73, 0x81, 0x5f, 0x18, 0x82, 0x21, 0xa4,},
            {0xc7, 0xa2, 0x73, 0x84, 0x4a, 0xc5, 0x4e, 0x83, 0x5a, 0x9c, 0xb6, 0x7f, 0x81, 0x05, 0x76, 0x02,},
            {0x54, 0x1f, 0x52, 0xbb, 0xf4, 0x3e, 0xce, 0x4e, 0x2a, 0x95, 0xc8, 0xe0, 0x1f, 0x65, 0x6d, 0xef,},
            {0x17, 0x97, 0x3b, 0xd4, 0x0d, 0xf3, 0x48, 0x15, 0x24, 0x4f, 0x99, 0x0c, 0xbf, 0x12, 0xbe, 0x5d,},
            {0x6b, 0x0b, 0x36, 0x0d, 0x56, 0x32, 0x80, 0xcd, 0xb1, 0x7d, 0x56, 0xc9, 0x08, 0xe1, 0xf5, 0xff,},
            {0xed, 0x00, 0xe1, 0x3b, 0x18, 0x4b, 0xf1, 0xc2, 0x72, 0x6b, 0x8b, 0x54, 0xff, 0xd2, 0xee, 0xe0,},
            {0xa7, 0xd9, 0x46, 0x13, 0x8f, 0xf9, 0xed, 0xf5, 0x36, 0x4a, 0x5a, 0x23, 0xaf, 0xca, 0xe0, 0x63,},
            {0x9e, 0x73, 0x14, 0xb7, 0x54, 0x5c, 0xec, 0xa3, 0x8b, 0x9a, 0x55, 0x49, 0xe4, 0xfb, 0x0b, 0xe8,},
            {0x58, 0x6c, 0x62, 0xc6, 0x84, 0x89, 0xd1, 0x68, 0xae, 0xe6, 0x5b, 0x88, 0x9a, 0xb9, 0x12, 0x75,},
            {0xe6, 0x71, 0x52, 0xa6, 0x4c, 0xa3, 0xd1, 0x47, 0xc4, 0xab, 0x84, 0x1e, 0x2f, 0x2e, 0x7a, 0x99,},
            {0x7f, 0x1c, 0x7a, 0xea, 0x90, 0x8d, 0xe5, 0x2e, 0x3e, 0x9e, 0x08, 0x83, 0xee, 0xa8, 0x16, 0xaf,},
            {0xde, 0x82, 0x7a, 0xbf, 0x92, 0xb7, 0x33, 0x92, 0x3f, 0x35, 0x33, 0x0d, 0xb5, 0xef, 0x4a, 0x34,},
            {0x59, 0x75, 0x63, 0x64, 0x0f, 0x37, 0x9a, 0xc5, 0x37, 0x67, 0x8e, 0xe2, 0x35, 0x4c, 0x7d, 0xf9,},
            {0x28, 0x4d, 0x03, 0x30, 0x3a, 0x45, 0x3a, 0x59, 0x3d, 0x78, 0xf7, 0xfa, 0xdc, 0x90, 0x62, 0xcb,},
            {0x91, 0x4a, 0xc7, 0xa2, 0x59, 0x7f, 0x63, 0xb7, 0xc0, 0xfd, 0xe5, 0xab, 0x8d, 0x4e, 0xad, 0x9c,},
            {0x0d, 0x51, 0x15, 0xa4, 0x4b, 0xa4, 0x55, 0xee, 0x3a, 0x45, 0x3b, 0x95, 0xce, 0x87, 0xc3, 0xcb,},
            {0x54, 0x9b, 0x93, 0x9d, 0x0b, 0xf1, 0xd8, 0x94, 0x83, 0x37, 0x88, 0x5a, 0x84, 0xce, 0x79, 0x14,},
            {0x6c, 0x17, 0x97, 0x69, 0xcd, 0x34, 0x8a, 0xeb, 0xd2, 0xfb, 0x13, 0x57, 0x8c, 0x72, 0xb4, 0x6c,},
            {0xaa, 0xd0, 0x36, 0xc1, 0x38, 0xc9, 0x57, 0xe0, 0x68, 0x2a, 0x00, 0xee, 0x2f, 0x86, 0x40, 0x8b,},
            {0x21, 0xb1, 0xee, 0xc4, 0x2f, 0xb6, 0x70, 0xbf, 0xee, 0x90, 0x44, 0xff, 0x4e, 0xd7, 0x3a, 0x26,},
            {0x05, 0x93, 0xa1, 0xd6, 0x29, 0x97, 0xed, 0x37, 0x46, 0x53, 0xc9, 0x17, 0x46, 0x3f, 0x14, 0xeb,},
            {0x11, 0x3d, 0x31, 0x62, 0x77, 0x19, 0xf9, 0x1e, 0xa0, 0xf1, 0xff, 0xc6, 0x86, 0x57, 0xe2, 0x4e,},
            {0xb3, 0x39, 0x4c, 0xf7, 0x2d, 0xe0, 0x6a, 0xdd, 0x0e, 0x73, 0x14, 0xf0, 0xc2, 0x52, 0xc4, 0xd6,},
            {0x92, 0x2a, 0x98, 0xda, 0x9d, 0x35, 0xc3, 0x41, 0xe2, 0x45, 0x6b, 0xe4, 0xcd, 0x63, 0x89, 0xd2,},
            {0x59, 0x6b, 0x62, 0x30, 0xf7, 0x57, 0xb3, 0x4a, 0xa2, 0xdc, 0xea, 0x50, 0xcb, 0xb2, 0x8d, 0x4d,},
            {0xc2, 0x4e, 0xe4, 0x97, 0xd5, 0x5b, 0x7e, 0x80, 0x06, 0x84, 0xdf, 0x75, 0x65, 0x59, 0xee, 0x48,},
            {0x5e, 0x9c, 0xb6, 0xa1, 0x36, 0x68, 0x1e, 0xd4, 0x5e, 0x2b, 0x9d, 0xe4, 0xdc, 0x01, 0x81, 0x77,},
            {0xbf, 0xfa, 0x39, 0xca, 0x86, 0x56, 0xd3, 0x04, 0x79, 0x33, 0xed, 0xfe, 0x9d, 0x81, 0x78, 0xb2,},
            {0x18, 0x22, 0x94, 0x18, 0xa1, 0xd0, 0x79, 0x5a, 0x35, 0x7a, 0x80, 0x3a, 0x81, 0x34, 0xae, 0xa3,},
            {0x4a, 0x3e, 0x96, 0xff, 0x53, 0x47, 0x4e, 0x2e, 0x73, 0x7b, 0x69, 0x57, 0x1a, 0x77, 0xb0, 0x6e,},
            {0xfe, 0xd5, 0xf0, 0xf9, 0xd0, 0x37, 0x72, 0x84, 0x2e, 0x2f, 0x57, 0x2f, 0x63, 0xf1, 0x94, 0x50,},
            {0x39, 0x33, 0x58, 0x86, 0xc1, 0xf9, 0x42, 0x63, 0xc4, 0x0c, 0x66, 0x29, 0xc6, 0xbc, 0x44, 0x6f,},
            {0xee, 0xa5, 0xf9, 0x3b, 0xb3, 0x87, 0x10, 0xb0, 0x8b, 0x2c, 0x46, 0x97, 0x19, 0x8b, 0xbf, 0x9f,},
            {0x80, 0x6e, 0xc7, 0xb6, 0x70, 0x4f, 0x72, 0x0e, 0x37, 0x43, 0x12, 0x06, 0x61, 0x66, 0xd4, 0x3a,},
            {0x6e, 0x69, 0xed, 0x9d, 0xf0, 0xc9, 0x39, 0xb4, 0x9d, 0xaf, 0xee, 0xae, 0x60, 0x47, 0xb2, 0xa2,},
            {0x93, 0xc7, 0x7b, 0xf2, 0x98, 0xb6, 0xf9, 0xc7, 0x94, 0xa2, 0x30, 0x17, 0x7f, 0x2f, 0xd7, 0x38,},
            {0xff, 0xad, 0x9c, 0xd9, 0x8c, 0x2a, 0xa8, 0x75, 0xda, 0xff, 0x3a, 0x2a, 0x4c, 0xe6, 0x0c, 0xe6,},
            {0x4d, 0x99, 0x2f, 0xfd, 0xf9, 0x4a, 0x93, 0xcd, 0xcd, 0x64, 0xef, 0x76, 0x57, 0xf5, 0x10, 0xe3,},
            {0x32, 0x70, 0x62, 0x4e, 0x24, 0xe0, 0xa1, 0x1e, 0xa1, 0x86, 0xe0, 0x96, 0xbe, 0x1b, 0xce, 0x9b,},
            {0x31, 0xe8, 0xbb, 0xe0, 0xcb, 0x4e, 0xff, 0x51, 0x1f, 0xff, 0xc7, 0xc4, 0x09, 0x34, 0x31, 0x77,},
            {0xcb, 0xe1, 0x7d, 0x05, 0x87, 0x9a, 0xd9, 0x07, 0x64, 0x8a, 0x12, 0xa0, 0x70, 0x16, 0xab, 0x5b,},
            {0x88, 0x48, 0xd4, 0x43, 0x70, 0xe9, 0x8b, 0xe2, 0xd5, 0xd2, 0x8b, 0x46, 0x36, 0x6a, 0x0a, 0xfc,},
            {0xb7, 0xff, 0xd1, 0xb2, 0x42, 0x10, 0x76, 0xa9, 0x0c, 0xb5, 0xcf, 0x65, 0x54, 0x09, 0x5e, 0x0c,},
            {0x6a, 0x6b, 0x66, 0x6c, 0xd5, 0x23, 0xa8, 0xf6, 0xbb, 0xd8, 0x84, 0xfe, 0x1f, 0xd1, 0x05, 0x0c,},
            {0xa8, 0xfe, 0x8a, 0x83, 0x50, 0xfb, 0xf5, 0xc8, 0x05, 0xf1, 0x8c, 0xbd, 0x30, 0x13, 0x62, 0x24,},
            {0xcc, 0xe7, 0x11, 0x7a, 0xee, 0x82, 0x36, 0xf2, 0xeb, 0x3a, 0x96, 0x94, 0xd5, 0x7e, 0x62, 0xb5,},
            {0x3a, 0x25, 0xf0, 0xe4, 0xfc, 0x28, 0xb7, 0x0c, 0x6b, 0x30, 0x90, 0xba, 0xfe, 0xf6, 0x9f, 0x04,},
            {0x3f, 0x05, 0xe6, 0x26, 0x74, 0x9f, 0xc4, 0x8b, 0x81, 0x06, 0xf8, 0xe4, 0x44, 0x31, 0xdd, 0x4a,},
            {0x76, 0x68, 0x79, 0xf9, 0x76, 0x72, 0x16, 0x5c, 0x0a, 0xff, 0xd5, 0xfa, 0xdc, 0x77, 0x34, 0x5b,},
            {0x43, 0x71, 0xa0, 0x5a, 0xb6, 0x6c, 0x59, 0x8b, 0xc9, 0xc2, 0x84, 0x94, 0xa1, 0xdd, 0x2f, 0x0e,},
            {0x65, 0xf8, 0x5b, 0xd3, 0xa2, 0xa5, 0xf1, 0xba, 0x1f, 0x22, 0xb6, 0xef, 0xd6, 0xe0, 0x02, 0x66,},
            {0x76, 0xcf, 0x61, 0xda, 0xe5, 0x4b, 0x22, 0xef, 0xca, 0x6a, 0x9f, 0x22, 0x8a, 0xaf, 0x66, 0x11,},
            {0x6c, 0xdc, 0xc2, 0xe3, 0x9f, 0xdb, 0xa2, 0x9f, 0x88, 0x53, 0x90, 0xab, 0x9d, 0xa4, 0x84, 0xda,},
            {0xe1, 0xee, 0xac, 0xea, 0xcc, 0x3b, 0x67, 0xb2, 0xd8, 0xe4, 0xe2, 0x61, 0x7b, 0x2f, 0xaa, 0x5a,},
            {0x0b, 0xd2, 0x9f, 0x6f, 0x4c, 0xe1, 0x0f, 0x17, 0x78, 0xd6, 0xb0, 0x2e, 0xd5, 0xab, 0x5a, 0x6d,},
            {0xad, 0x18, 0x9f, 0x15, 0x6a, 0x52, 0x26, 0x7c, 0xe0, 0x87, 0x45, 0x83, 0x5b, 0x65, 0xa6, 0x07,},
            {0x0f, 0x6b, 0x99, 0x71, 0x72, 0x25, 0x66, 0xd4, 0x3d, 0xec, 0x6b, 0x99, 0xe3, 0x1c, 0x21, 0x8f,},
            {0xa1, 0xa4, 0xc8, 0xfa, 0x4f, 0x3d, 0xf4, 0x66, 0xd3, 0xf3, 0x9c, 0x6f, 0x3d, 0x9e, 0x1a, 0x74,},
            {0x3b, 0x1a, 0x3d, 0xb8, 0x8c, 0xf0, 0xc2, 0x1f, 0xc1, 0xa6, 0xd8, 0xa7, 0x2d, 0x9e, 0xf9, 0x1d,},
            {0xd1, 0x48, 0x68, 0x02, 0xef, 0xc0, 0x00, 0x28, 0x56, 0xc3, 0x63, 0x5a, 0x8a, 0x69, 0x2e, 0xe5,},
            {0xee, 0xa1, 0x5f, 0x8f, 0x7c, 0xae, 0x19, 0x99, 0xfd, 0x56, 0x49, 0x31, 0xc2, 0x2c, 0x1c, 0x3c,},
            {0x63, 0xf5, 0xae, 0x63, 0x28, 0xc4, 0xdb, 0x93, 0x20, 0x79, 0x61, 0xee, 0x90, 0x6b, 0xd4, 0xa5,},
        };

        performTest(4, 8, vectors_sip128);
    }

    private void performTest(int cRounds, int dRounds, int[][] testvectorsInt)
        throws Exception
    {
        int n = testvectorsInt.length;
        int macSize = testvectorsInt[0].length;

        byte[][] testvectors = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            testvectors[i] = new byte[macSize];
            for (int j = 0; j < macSize; j++)
            {
                testvectors[i][j] = (byte)testvectorsInt[i][j];
            }
        }

        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");

        for (int i = 0; i < n; i++)
        {
            byte[] input = new byte[i];
            for (int j = 0; j < input.length; j++)
            {
                input[j] = (byte)j;
            }

            runMAC(cRounds, dRounds, testvectors[i], key, input);
        }

        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 100; ++i)
        {
            randomTest(cRounds, dRounds, random);
        }
    }

    private void runMAC(int cRounds, int dRounds, byte[] expected, byte[] key, byte[] input)
        throws Exception
    {
        runMAC(cRounds, dRounds, expected, key, input, UPDATE_BYTES);
        runMAC(cRounds, dRounds, expected, key, input, UPDATE_FULL);
        runMAC(cRounds, dRounds, expected, key, input, UPDATE_MIX);
    }

    private void runMAC(int cRounds, int dRounds, byte[] expected, byte[] key, byte[] input,
                        int updateType)
        throws Exception
    {
        SipHash128 mac = new SipHash128(cRounds, dRounds);
        mac.init(new KeyParameter(key));

        updateMAC(mac, input, updateType);

        byte[] output = new byte[mac.getMacSize()];
        int len = mac.doFinal(output, 0);
        if (len != output.length)
        {
            fail("Result length does not equal getMacSize() for doFinal(byte[],int)");
        }
        if (!areEqual(expected, output))
        {
            fail("Result does not match expected value for doFinal(byte[],int)");
        }
    }

    private void randomTest(int cRounds, int dRounds, SecureRandom random)
    {
        byte[] key = new byte[16];
        random.nextBytes(key);

        int length = 1 + RNGUtils.nextInt(random, 1024);
        byte[] input = new byte[length];
        random.nextBytes(input);

        SipHash128 mac = new SipHash128(cRounds, dRounds);
        mac.init(new KeyParameter(key));

        updateMAC(mac, input, UPDATE_BYTES);
        byte[] result1 = new byte[16];
        mac.doFinal(result1, 0);

        updateMAC(mac, input, UPDATE_FULL);
        byte[] result2 = new byte[16];
        mac.doFinal(result2, 0);

        updateMAC(mac, input, UPDATE_MIX);
        byte[] result3 = new byte[16];
        mac.doFinal(result3, 0);

        if (!Arrays.areEqual(result1, result2) ||
            !Arrays.areEqual(result1, result3))
        {
            fail("Inconsistent results in random test");
        }
    }

    private void updateMAC(SipHash128 mac, byte[] input, int updateType)
    {
        switch (updateType)
        {
        case UPDATE_BYTES:
        {
            for (int i = 0; i < input.length; ++i)
            {
                mac.update(input[i]);
            }
            break;
        }
        case UPDATE_FULL:
        {
            mac.update(input, 0, input.length);
            break;
        }
        case UPDATE_MIX:
        {
            int step = Math.max(1, input.length / 3);
            int pos = 0;
            while (pos < input.length)
            {
                mac.update(input[pos++]);
                int len = Math.min(input.length - pos, step);
                mac.update(input, pos, len);
                pos += len;
            }
            break;
        }
        default:
            throw new IllegalStateException();
        }
    }

    public static void main(String[] args)
    {
        runTest(new SipHash128Test());
    }
}
