module org.spongycastle.pg
{
    requires org.spongycastle.provider;

    exports org.spongycastle.bcpg;
    exports org.spongycastle.gpg;
    exports org.spongycastle.openpgp;
    exports org.spongycastle.bcpg.attr;
    exports org.spongycastle.bcpg.sig;
    exports org.spongycastle.gpg.keybox;
    exports org.spongycastle.gpg.keybox.bc;
    exports org.spongycastle.gpg.keybox.jcajce;
    exports org.spongycastle.openpgp.bc;
    exports org.spongycastle.openpgp.examples;
    exports org.spongycastle.openpgp.jcajce;
    exports org.spongycastle.openpgp.operator;
    exports org.spongycastle.openpgp.operator.bc;
    exports org.spongycastle.openpgp.operator.jcajce;
}
