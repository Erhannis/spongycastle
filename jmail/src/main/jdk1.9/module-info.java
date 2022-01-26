module org.spongycastle.mail
{
    requires org.spongycastle.provider;
    requires org.spongycastle.pkix;

    exports org.spongycastle.mail.smime;
    exports org.spongycastle.mail.smime.examples;
    exports org.spongycastle.mail.smime.handlers;
    exports org.spongycastle.mail.smime.util;
    exports org.spongycastle.mail.smime.validator;
}
