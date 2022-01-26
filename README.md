# The Bouncy Castle Crypto Package For Java

[![Build Status](https://travis-ci.org/bcgit/bc-java.svg?branch=master)](https://travis-ci.org/bcgit/bc-java)

The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms, it was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at [https://www.spongycastle.org](https://www.spongycastle.org).

The Legion also gratefully acknowledges the contributions made to this package by others (see [here](https://www.spongycastle.org/contributors.html) for the current list). If you would like to contribute to our efforts please feel free to get in touch with us or visit our [donations page](https://www.spongycastle.org/donate), sponsor some specific work, or purchase a support contract through [Crypto Workshop](https://www.cryptoworkshop.com).

The package is organised so that it contains a light-weight API suitable for use in any environment (including the newly released J2ME) with the additional infrastructure to conform the algorithms to the JCE framework.

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.spongycastle.org/licence.html). The OpenPGP library also includes a modified BZIP2 library which is licensed under the [Apache Software License, Version 2.0](https://www.apache.org/licenses/). 

**Note**: this source tree is not the FIPS version of the APIs - if you are interested in our FIPS version please contact us directly at  [office.spongycastle.org](mailto:office.spongycastle.org).

## Code Organisation

The clean room JCE, for use with JDK 1.1 to JDK 1.3 is in the jce/src/main/java directory. From JDK 1.4 and later the JCE ships with the JVM, the source for later JDKs follows the progress that was made in the later versions of the JCE. If you are using a later version of the JDK which comes with a JCE install please **do not** include the jce directory as a source file as it will clash with the JCE API installed with your JDK.

The **core** module provides all the functionality in the ligthweight APIs.

The **prov** module provides all the JCA/JCE provider functionality.

The **util** module is the home for code which is used by other modules that does not need to be in prov. At the moment this is largely ASN.1 classes for the PKIX module.

The **pkix** module is the home for code for X.509 certificate generation and the APIs for standards that rely on ASN.1 such
as CMS, TSP, PKCS#12, OCSP, CRMF, and CMP.

The **mail** module provides an S/MIME API built on top of CMS.

The **pg** module is the home for code used to support OpenPGP.

The **tls** module is the home for code used to a general TLS API and JSSE Provider.

The build scripts that come with the full distribution allow creation of the different releases by using the different source trees while excluding classes that are not appropriate and copying in the required compatibility classes from the directories containing compatibility classes appropriate for the distribution.

If you want to try create a build for yourself, using your own environment, the best way to do it is to start with the build for the distribution you are interested in, make sure that builds, and then modify your build scripts to do the required exclusions and file copies for your setup, otherwise you are likely to get class not found exceptions. The final caveat to this is that as the j2me distribution includes some compatibility classes starting in the java package, you need to use an obfuscator to change the package names before attempting to import a midlet using the BC API.


## Examples and Tests

To view some examples, look at the test programs in the packages:

*   **org.spongycastle.crypto.test**

*   **org.spongycastle.jce.provider.test**

*   **org.spongycastle.cms.test**

*   **org.spongycastle.mail.smime.test**

*   **org.spongycastle.openpgp.test**

*   **org.spongycastle.tsp.test**

There are also some specific example programs for dealing with SMIME and OpenPGP. They can be found in:

*   **org.spongycastle.mail.smime.examples**

*   **org.spongycastle.openpgp.examples**

## Mailing Lists

For those who are interested, there are 2 mailing lists for participation in this project. To subscribe use the links below and include the word subscribe in the message body. (To unsubscribe, replace **subscribe** with **unsubscribe** in the message body)

*   [announce-crypto-request.spongycastle.org](mailto:announce-crypto-request.spongycastle.org)  
    This mailing list is for new release announcements only, general subscribers cannot post to it.
*   [dev-crypto-request.spongycastle.org](mailto:dev-crypto-request.spongycastle.org)  
    This mailing list is for discussion of development of the package. This includes bugs, comments, requests for enhancements, questions about use or operation.

**NOTE:** You need to be subscribed to send mail to the above mailing list.

## Feedback and Contributions

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto.spongycastle.org](mailto:feedback-crypto.spongycastle.org), if you want to help this project survive please consider [donating](https://www.spongycastle.org/donate).

For bug reporting/requests you can report issues here on github, or via feedback-crypto if required. We will accept pull requests based on this repository as well, but only on the basis that any code included may be distributed under the [Bouncy Castle License](https://www.spongycastle.org/licence.html).

## Finally

Enjoy!
