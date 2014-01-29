openssh-java
============

Support for reading OpenSSH RSA keys on the JVM.

Usage
=====

```java
SshRsaCrypto rsa = new SshRsaCrypto();
PublicKey publicKey = rsa.readPublicKey(rsa.slurpPublicKey(publicKeyBody));
PrivateKey privateKey = rsa.readPrivateKey(rsa.slurpPrivateKey(privateKeyBody));
```

now you're in the Java Crypto API land and can do this sort of thing:

```java
private byte[] encrypt(String text, PublicKey key) throws GeneralSecurityException {
  Cipher cipher = Cipher.getInstance(RSA);
  cipher.init(Cipher.ENCRYPT_MODE, key);
  return cipher.doFinal(text.getBytes());
}

private String decrypt(byte[] text, PrivateKey key) throws GeneralSecurityException {
  Cipher cipher = Cipher.getInstance(RSA);
  cipher.init(Cipher.DECRYPT_MODE, key);
  return new String(cipher.doFinal(text));
}

...

String message = "Hello World!!1!";
byte[] cipherText = encrypt(message, publicKey);
String decrypted = decrypt(cipherText, privateKey);
assertEquals(message, decrypted);
```

Installation
============

Releases are in Maven Central:

```xml
<dependency>
  <groupId>com.github.fommil</groupId>
  <artifactId>openssh-java</artifactId>
  <version>1.0</version>
</dependency>
```


Donations
=========

Please consider supporting the maintenance of this open source project with a donation:

[![Donate via Paypal](https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=B2HW5ATB8C3QW&lc=GB&item_name=openssh-java&currency_code=GBP&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)

Licence
=======

Copyright (C) 2014 Samuel Halliday

This library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this library; if not, see http://www.gnu.org/licenses/

Contributing
============

Contributors are encouraged to fork this repository and issue pull
requests. Contributors implicitly agree to assign an unrestricted licence
to Sam Halliday, but retain the copyright of their code (this means
we both have the freedom to update the licence for those contributions).
