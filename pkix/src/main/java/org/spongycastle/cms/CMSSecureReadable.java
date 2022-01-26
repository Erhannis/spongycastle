package org.spongycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.spongycastle.asn1.ASN1ObjectIdentifier;

interface CMSSecureReadable
{
    ASN1ObjectIdentifier getContentType();

    InputStream getInputStream()
            throws IOException, CMSException;
}
