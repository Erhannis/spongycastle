package org.spongycastle.mime.smime;

import java.io.IOException;
import java.io.InputStream;

import org.spongycastle.mime.BasicMimeParser;
import org.spongycastle.mime.Headers;
import org.spongycastle.mime.MimeParser;
import org.spongycastle.mime.MimeParserProvider;
import org.spongycastle.operator.DigestCalculatorProvider;

public class SMimeParserProvider
    implements MimeParserProvider
{
    private final String defaultContentTransferEncoding;
    private final DigestCalculatorProvider digestCalculatorProvider;

    public SMimeParserProvider(String defaultContentTransferEncoding, DigestCalculatorProvider digestCalculatorProvider)
    {
        this.defaultContentTransferEncoding = defaultContentTransferEncoding;
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    public MimeParser createParser(InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
            SMimeUtils.autoBuffer(source));
    }

    public MimeParser createParser(Headers headers, InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
            headers, SMimeUtils.autoBuffer(source));
    }
}
