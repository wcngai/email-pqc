Below are **end-to-end sample implementations** that a mail client could call to **sign (ML-DSA), encrypt (ML-KEM via CMS KEMRecipientInfo), send**, and then **receive, decrypt, and verify**. I’m using **Java + Bouncy Castle 1.81** because it already exposes the CMS KEMRecipientInfo API and PQC primitives (ML-KEM, ML-DSA). The flow matches **RFC 9629** (CMS + KEMRecipientInfo) and the ML-KEM-for-CMS draft (as of 2025) including HKDF and AES Key Wrap choices. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc9629?utm_source=chatgpt.com), [downloads.bouncycastle.org](https://downloads.bouncycastle.org/java/docs/bcutil-jdk14-javadoc/org/bouncycastle/asn1/cms/KEMRecipientInfo.html?utm_source=chatgpt.com))

Notes up front  
• These snippets show **sign-then-encrypt** (common S/MIME practice).  
• For KEMRecipientInfo we use **HKDF** and **AES-KW** (or KWP) as per RFC 9629 and the ML-KEM-in-CMS draft. For **ML-KEM-768/1024**, use **AES-256-Wrap**; for **ML-KEM-512**, **AES-128-Wrap** is sufficient. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc9629?utm_source=chatgpt.com))  
• Bouncy Castle exposes KEMRecipientInfo (and ML-KEM/ML-DSA) via the **BC/BCPQC provider** family. ([downloads.bouncycastle.org](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/jce/provider/BouncyCastleProvider.html?utm_source=chatgpt.com))  
• If you need absolute conformance knobs (e.g., HKDF-SHA-384 with ML-KEM-768), adjust the KDF OID (see RFC 8619 OIDs). ([downloads.bouncycastle.org](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/asn1/pkcs/PKCSObjectIdentifiers.html?utm_source=chatgpt.com))

**0) Maven (add these)**

&lt;dependencies&gt;

&lt;!-- Core crypto + PQC (ML-KEM, ML-DSA) --&gt;

&lt;dependency&gt;

&lt;groupId&gt;org.bouncycastle&lt;/groupId&gt;

&lt;artifactId&gt;bcprov-jdk18on&lt;/artifactId&gt;

&lt;version&gt;1.81&lt;/version&gt;

&lt;/dependency&gt;

&lt;dependency&gt;

&lt;groupId&gt;org.bouncycastle&lt;/groupId&gt;

&lt;artifactId&gt;bcpkix-jdk18on&lt;/artifactId&gt;

&lt;version&gt;1.81&lt;/version&gt;

&lt;/dependency&gt;

&lt;!-- Optional: S/MIME/MIME helpers; you can also assemble MIME manually --&gt;

&lt;dependency&gt;

&lt;groupId&gt;org.bouncycastle&lt;/groupId&gt;

&lt;artifactId&gt;bcmail-jdk18on&lt;/artifactId&gt;

&lt;version&gt;1.81&lt;/version&gt;

&lt;/dependency&gt;

&lt;!-- Optional if you package into MIME emails --&gt;

&lt;dependency&gt;

&lt;groupId&gt;org.eclipse.angus&lt;/groupId&gt;

&lt;artifactId&gt;angus-mail&lt;/artifactId&gt;

&lt;version&gt;2.0.3&lt;/version&gt;

&lt;/dependency&gt;

&lt;/dependencies&gt;

If you installed the **BCPQC** add-on (e.g., with BC-FIPS), you can also Security.addProvider(new BouncyCastlePQCProvider()); and set provider to "BCPQC". Otherwise, the general “BC” provider includes PQC in 1.79+ (non-FIPS). ([Javadoc](https://javadoc.io/doc/org.bouncycastle/bctls-jdk14/1.80/releasenotes.html?utm_source=chatgpt.com))

**1) Shared helpers (load PEM keys/certs, provider setup)**

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import org.bouncycastle.util.io.pem.PemReader;

import org.bouncycastle.openssl.PEMParser;

import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import org.bouncycastle.cert.X509CertificateHolder;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.\*;

import java.security.\*;

import java.security.cert.X509Certificate;

public final class PqcEmailCryptoUtil {

private static final String\[\] PROVIDERS = {"BCPQC", "BC"}; // prefer BCPQC if present

public static String pickProvider() {

for (String p : PROVIDERS) if (Security.getProvider(p) != null) return p;

// register defaults

Security.addProvider(new BouncyCastleProvider());

if (Security.getProvider("BCPQC") == null) {

try { Security.addProvider(new BouncyCastlePQCProvider()); } catch (Throwable ignored) {}

}

return (Security.getProvider("BCPQC") != null) ? "BCPQC" : "BC";

}

public static X509Certificate readCertificatePEM(File pem) throws Exception {

try (PEMParser pp = new PEMParser(new FileReader(pem))) {

Object o = pp.readObject();

X509CertificateHolder h = (X509CertificateHolder) o;

return new JcaX509CertificateConverter().setProvider("BC").getCertificate(h);

}

}

public static PrivateKey readPrivateKeyPEM(File pem, String provider) throws Exception {

try (PEMParser pp = new PEMParser(new FileReader(pem))) {

Object o = pp.readObject();

return new JcaPEMKeyConverter().setProvider(provider).getPrivateKey(

(org.bouncycastle.asn1.pkcs.PrivateKeyInfo) o);

}

}

private PqcEmailCryptoUtil() {}

}

**2) Sender side (sign-then-encrypt; output S/MIME CMS bytes)**

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import org.bouncycastle.cert.jcajce.JcaCertStore;

import org.bouncycastle.cms.\*;

import org.bouncycastle.cms.jcajce.\*;

import org.bouncycastle.operator.ContentSigner;

import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.PrivateKey;

import java.security.Security;

import java.security.cert.X509Certificate;

import java.util.Arrays;

import java.util.List;

public class PqcEmailSender {

/\*\*

\* Build a CMS object that is Signed (ML-DSA) then Encrypted (ML-KEM KEMRecipientInfo + AES-GCM content).

\*

\* @param cleartext payload bytes

\* @param signerKey ML-DSA private key (e.g., Dilithium3)

\* @param signerCert signer certificate (ML-DSA public key)

\* @param recipientsKemCerts recipients' ML-KEM certificates

\*/

public static byte\[\] signThenEncrypt(byte\[\] cleartext,

PrivateKey signerKey,

X509Certificate signerCert,

List&lt;X509Certificate&gt; recipientsKemCerts) throws Exception {

final String provider = PqcEmailCryptoUtil.pickProvider();

// --- 1) Sign cleartext (ML-DSA / Dilithium)

// Use an ML-DSA family algorithm name recognized by your provider.

// Common choices: "Dilithium2", "Dilithium3", "Dilithium5" or "ML-DSA-44/65/87"

// Adjust to your chosen parameter set / provider naming.

ContentSigner signer = new JcaContentSignerBuilder("Dilithium3")

.setProvider(provider)

.build(signerKey);

CMSSignedDataGenerator sGen = new CMSSignedDataGenerator();

sGen.addSignerInfoGenerator(

new JcaSignerInfoGeneratorBuilder(

new JcaDigestCalculatorProviderBuilder().setProvider(provider).build()

).build(signer, signerCert)

);

sGen.addCertificates(new JcaCertStore(Arrays.asList(signerCert)));

CMSTypedData msg = new CMSProcessableByteArray(cleartext);

CMSSignedData signed = sGen.generate(msg, true);

// --- 2) Encrypt the signed blob using CMS EnvelopedData + KEMRecipientInfo (RFC 9629)

CMSEnvelopedDataGenerator eGen = new CMSEnvelopedDataGenerator();

// Add a KEM recipient for each ML-KEM cert

for (X509Certificate kemCert : recipientsKemCerts) {

JceKEMRecipientInfoGenerator kemRecip = new JceKEMRecipientInfoGenerator(kemCert);

// KDF: HKDF with SHA-256/384/512 (RFC 8619 OIDs). Pick based on ML-KEM level if you like.

// For broad interop, HKDF-SHA256 is fine and widely referenced; set others if your profile requires.

ASN1ObjectIdentifier hkdf = PKCSObjectIdentifiers.id_alg_hkdf_with_sha256;

kemRecip.setKDF(hkdf); // HKDF info/salt is handled per RFC 9629 / draft

// AES Key Wrap size (RFC 3394 / RFC 5649). 256-bit wrap is typical for ML-KEM-768/1024.

kemRecip.setKeySize(256); // KEK size in bits for wrapping the CEK

kemRecip.setWrapAlgorithm(NISTObjectIdentifiers.id_aes256_wrap);

eGen.addRecipientInfoGenerator(kemRecip);

}

// Content encryption for the EnvelopedData (the content under the CEK)

OutputEncryptor contentEncryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM)

.setProvider(provider)

.build();

CMSEnvelopedData env = eGen.generate(new CMSProcessableByteArray(signed.getEncoded()), contentEncryptor);

return env.getEncoded();

}

}

**3) Receiver side (decrypt + verify)**

import org.bouncycastle.cms.\*;

import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import java.security.PrivateKey;

import java.security.Security;

import java.security.cert.X509Certificate;

import java.util.Collection;

public class PqcEmailReceiver {

/\*\*

\* Decrypt a CMS EnvelopedData (KEMRecipientInfo) and verify the embedded SignedData.

\*

\* @param envelopedCms bytes of application/pkcs7-mime (smime-type=enveloped-data)

\* @param recipientKemPrivateKey receiver's ML-KEM private key

\* @param signerCert expected signer certificate (to verify ML-DSA)

\* @return the original cleartext if verification succeeds

\*/

public static byte\[\] decryptAndVerify(byte\[\] envelopedCms,

PrivateKey recipientKemPrivateKey,

X509Certificate signerCert) throws Exception {

final String provider = PqcEmailCryptoUtil.pickProvider();

// --- 1) Parse and KEM-decrypt the EnvelopedData

CMSEnvelopedData env = new CMSEnvelopedData(envelopedCms);

RecipientInformationStore ris = env.getRecipientInfos();

// For simplicity, pick the first KEM recipient info. In a real client, match by RecipientId.

RecipientInformation ri = ris.getRecipients().iterator().next();

// JceKEMRecipient performs the ML-KEM decapsulation and then unwraps the CEK (AES-KW) per RFC 9629.

Recipient kemRecipient = new JceKEMRecipient(recipientKemPrivateKey).setProvider(provider);

byte\[\] signedBlob = ri.getContent(kemRecipient);

// --- 2) Verify the inner SignedData (ML-DSA / Dilithium)

CMSSignedData signed = new CMSSignedData(signedBlob);

SignerInformationStore signers = signed.getSignerInfos();

Collection&lt;SignerInformation&gt; c = signers.getSigners();

for (SignerInformation s : c) {

boolean ok = s.verify(new JcaSimpleSignerInfoVerifierBuilder()

.setProvider(provider)

.build(signerCert));

if (!ok) throw new SecurityException("Signature verification failed");

}

// If you signed "detached", extract content differently; here we used encapsulated content.

return (byte\[\]) signed.getSignedContent().getContent();

}

}

**4) (Optional) Wrap into an actual email**

If you want to send this as a real S/MIME message:

// Build the CMS bytes with PqcEmailSender.signThenEncrypt(...)

byte\[\] smimeP7m = ...;

import jakarta.mail.\*;

import jakarta.mail.internet.\*;

import java.util.Properties;

Properties props = new Properties();

props.put("mail.smtp.host", "smtp.example.com");

Session session = Session.getInstance(props);

MimeBodyPart pkcs7Part = new MimeBodyPart();

pkcs7Part.setDataHandler(new DataHandler(new ByteArrayDataSource(smimeP7m, "application/pkcs7-mime")));

pkcs7Part.setFileName("smime.p7m");

pkcs7Part.setHeader("Content-Type", "application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m");

pkcs7Part.setHeader("Content-Transfer-Encoding", "base64");

MimeMessage msg = new MimeMessage(session);

msg.setFrom("<alice@example.com>");

msg.setRecipients(Message.RecipientType.TO, "<bob@example.com>");

msg.setSubject("PQC S/MIME test");

msg.setContent(pkcs7Part.getContent(), pkcs7Part.getContentType());

// Transport.send(msg); // actually send

On receive, extract the application/pkcs7-mime part into a byte\[\] and call PqcEmailReceiver.decryptAndVerify(...).

**A few practical tips**

- **KDF & Wrap choices:** For ML-KEM-768/1024 profiles, **AES-256-Wrap** is RECOMMENDED; use **HKDF** with a hash whose strength matches your target (SHA-256/384/512). The OIDs for HKDF-SHA2 are defined in **RFC 8619**; AES-KW/KWP are in **RFC 3394 / SP 800-38F**. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kyber-11), [downloads.bouncycastle.org](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/asn1/pkcs/PKCSObjectIdentifiers.html?utm_source=chatgpt.com), [NIST Publications](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf?utm_source=chatgpt.com))
- **Certificates:** You’ll need **ML-KEM recipient certs** and **ML-DSA signer certs** (or a hybrid profile) issued by a CA that supports these algorithms. (Bouncy Castle and EJBCA publish how-tos for issuing ML-KEM/ML-DSA certs.) ([docs.keyfactor.com](https://docs.keyfactor.com/ejbca/9.2.2/tutorial-issue-an-ml-kem-end-entity-certificate?utm_source=chatgpt.com))
- **Why CMS + KEMRecipientInfo?** It’s the standardized way to carry KEM ciphertext, KDF, KEK length, and the key-wrap algorithm inside CMS for store-and-forward email. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc9629?utm_source=chatgpt.com))
- **Content cipher:** I used **AES-GCM** for the actual message payload (CEK). You can swap to AES-256-CBC+HMAC if your compatibility matrix requires it; CMS supports both. ([Stack Overflow](https://stackoverflow.com/questions/60889073/how-to-encrypt-a-cms-envelopeddata-value-with-aes-gcm-using-bouncycastle?utm_source=chatgpt.com))

**References (for the curious)**

- **RFC 9629 – KEMRecipientInfo for CMS** (Aug 2024): defines how KEM, HKDF, KEK length and AES-KW appear in CMS. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc9629?utm_source=chatgpt.com))
- **ML-KEM in CMS draft (-11, Jul 2025)**: profiles KDF + AES-Wrap choices for ML-KEM-512/768/1024; certificate conventions. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kyber-11))
- **HKDF algorithm identifiers (RFC 8619)** used above. ([downloads.bouncycastle.org](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/asn1/pkcs/PKCSObjectIdentifiers.html?utm_source=chatgpt.com))
- **AES-KW / AES-KWP** background/specs. ([IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc5649?utm_source=chatgpt.com), [NIST Publications](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf?utm_source=chatgpt.com))
- **Bouncy Castle**: JCE provider with ML-KEM/ML-DSA and CMS KEMRecipientInfo APIs used here. ([downloads.bouncycastle.org](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/jce/provider/BouncyCastleProvider.html?utm_source=chatgpt.com))

If you want this ported to another stack (OpenSSL 3.5+/oqs-provider C, Go+circl with a CMS layer, or Python for test vectors), I can drop equivalent sender/receiver samples, too.