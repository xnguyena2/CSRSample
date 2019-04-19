import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import sun.misc.BASE64Encoder;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import org.bouncycastle.util.Store;
import java.util.*;


public class BaseFunction {

    private static final ASN1ObjectIdentifier ROLE = new ASN1ObjectIdentifier("2.5.4.120").intern();
    private static final BouncyCastleProvider ProviderBC = new BouncyCastleProvider();
    private static final String SignatureAlgorithm = "SHA256withRSA";//SHA256withECDSA
    private static final String OrgUrl = "multiledgers.com";
    private static final String CertificateFactoryType = "X.509";
    private static final String KeyPairGeneratorAlgorithm = "RSA";
    private static final String KeyStoreType = "JKS";
    private static final String CertPathValidatorAlgorithm = "PKIX";
    private static final Date NotBeforeDate = Date.from(LocalDate.of(2018, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());
    private static final Date NotAfterDate = Date.from(LocalDate.of(2020, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());

    public class CertificateChainSigned {
        public String UserCert;
        public String IntermedialCert;

        public CertificateChainSigned(String UserCert, String IntermedialCert) {
            this.IntermedialCert = IntermedialCert;
            this.UserCert = UserCert;
        }
    }

    public class X509CertificateHolderExtend extends X509CertificateHolder {

        public X509CertificateHolderExtend(byte[] bytes) throws IOException {
            super(bytes);
        }

        public X509CertificateHolderExtend(org.bouncycastle.asn1.x509.Certificate certificate) {
            super(certificate);
        }

        public X509Certificate convertCa() throws Exception {
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            converter.setProvider(ProviderBC);
            return converter.getCertificate(this);
        }
    }

    public static class X509CertificateFactory {

        private CertificateFactory delegate;

        public X509CertificateFactory() throws Exception {
            delegate = CertificateFactory.getInstance(CertificateFactoryType, ProviderBC);
        }

        public CertPath generateCertPath(List<X509Certificate> certificates) throws Exception {
            return delegate.generateCertPath(certificates);
        }

    }

    static class PemFile {
        private PemObject pemObject;

        public PemFile(Key key, String description) {
            pemObject = new PemObject(description, key.getEncoded());
        }

        public void write(String fileName) throws Exception {
            PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(fileName)));
            pemWriter.writeObject(pemObject);
            pemWriter.close();
        }
    }

    public static X509Certificate convertCa(X509CertificateHolder holder) throws Exception {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(ProviderBC);
        return converter.getCertificate(holder);
    }

    public static KeyPair generateRSAKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(KeyPairGeneratorAlgorithm, ProviderBC);
        return gen.generateKeyPair();
    }


    public static X509Certificate generateCertificate(PublicKey subjectPublicKey, X500Name subjectDN, X500Name issuerDN,
                                                      KeyPair issuerKeyPair) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] id = new byte[20];
        Vector<KeyPurposeId> keyPurposeIds = new Vector<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth);
        keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);
        random.nextBytes(id);
        BigInteger serial = new BigInteger(160, random);
        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
        BasicConstraints constraints = new BasicConstraints(true);
        ExtendedKeyUsage usageEx = new ExtendedKeyUsage(keyPurposeIds);
        ContentSigner signer = new JcaContentSignerBuilder(SignatureAlgorithm)
                .build(issuerKeyPair.getPrivate());
        JcaX509v3CertificateBuilder certificate = new JcaX509v3CertificateBuilder(
                issuerDN,
                serial,
                NotBeforeDate,
                NotAfterDate,
                subjectDN,
                subjectPublicKey);
        certificate.addExtension(
                Extension.basicConstraints,
                true,
                constraints.getEncoded()
        );
        certificate.addExtension(Extension.keyUsage, false, usage.getEncoded());
        certificate.addExtension(
                Extension.extendedKeyUsage,
                false,
                usageEx.getEncoded()
        );

        // build BouncyCastle certificate
        X509CertificateHolder result = certificate.build(signer);

        if (!result.isValidOn(new Date()))
            throw new Exception("Invalid date!");
        if (!result.isSignatureValid(new JcaContentVerifierProviderBuilder().build(issuerKeyPair.getPublic())))
            throw new Exception("Invalid signature public key");
        return convertCa(result);
    }

    public static void SaveKeyPemFile(Key key, String description, String fileName) throws Exception {
        PemFile pemFile = new PemFile(key, description);
        pemFile.write(fileName);
    }

    public static String GeneCSR(KeyPair keyPair, X500Name subjectDN) throws Exception  {
        ContentSigner signGen = new JcaContentSignerBuilder(SignatureAlgorithm).setProvider(ProviderBC).build(keyPair.getPrivate());
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subjectDN, keyPair.getPublic());
        PKCS10CertificationRequest request = builder.build(signGen);
        return Base64.toBase64String(request.getEncoded());
    }

    public static void SaveKeyStore(String keyEntry, KeyPair keyPair,X509Certificate[] certChain,String pwd ,String fileName)throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStoreType);
        keyStore.load(null,null);
        keyStore.setKeyEntry(keyEntry, keyPair.getPrivate(), pwd.toCharArray(), certChain);
        FileOutputStream fileSave = new FileOutputStream(fileName);
        keyStore.store(fileSave, pwd.toCharArray());
        fileSave.close();
    }

    public static KeyStore LoadKeyStore(String fileName, String pwd ) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStoreType);
        keyStore.load(new FileInputStream(fileName), pwd.toCharArray());
        return keyStore;
    }

    public static KeyPair GetKeyPair(KeyStore keyStore, String keyEntry, String pwd) throws Exception {
        PrivateKey privateKey = (PrivateKey)keyStore.getKey(keyEntry, pwd.toCharArray());
        X509Certificate cer = (X509Certificate)(keyStore.getCertificate(keyEntry));
        return new KeyPair(cer.getPublicKey(), privateKey);
    }

    public static CertPathValidatorResult validateCertificateChain(X509Certificate trustedRoot, List<X509Certificate> certificates)throws Exception  {
        if(certificates.isEmpty()) {
            throw new Exception("Certificate path must contain at least one certificate");
        }
        return validateCertPath(trustedRoot, buildCertPath(certificates));
    }

    public static CertPathValidatorResult validateCertPath(X509Certificate trustedRoot, CertPath certPath)throws Exception  {
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        trustAnchors.add(new TrustAnchor(trustedRoot, null));
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);
        return CertPathValidator.getInstance(CertPathValidatorAlgorithm, ProviderBC).validate(certPath, params);
    }

    public static CertPath buildCertPath(List<X509Certificate> certificates) throws Exception {
        return new X509CertificateFactory().generateCertPath(certificates);
    }

    public static X509Certificate signCSR(String pemCSR,KeyPair rootKeyPair,X509Certificate rootCACert) throws Exception  {
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(pemCSR));
        JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest =new JcaPKCS10CertificationRequest(csr);
        return generateCertificate(jcaPKCS10CertificationRequest.getPublicKey(), jcaPKCS10CertificationRequest.getSubject(),
                X500Name.getInstance(rootCACert.getSubjectX500Principal().getEncoded()), rootKeyPair);
    }

    public static String signData(byte[] datas, PrivateKey privateKey, List<X509Certificate> listCertificate) throws Exception{
        CMSProcessableByteArray msg = new CMSProcessableByteArray(datas);
        JcaCertStore certs = new JcaCertStore(listCertificate);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder(SignatureAlgorithm).setProvider(ProviderBC).build(privateKey);
        gen.addSignerInfoGenerator( new JcaSignerInfoGeneratorBuilder( new JcaDigestCalculatorProviderBuilder().setProvider(ProviderBC).build()).build(sha1Signer, listCertificate.get(listCertificate.size()-1)));
        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(msg, true);
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(sigData.getEncoded());
    }

    public static List<X509Certificate> GetListCertificateFromSignature(String sig) throws Exception {
        List<X509Certificate> result = new ArrayList<X509Certificate>();
        CMSSignedData signedData = new CMSSignedData(Base64.decode(sig));
        Store<X509CertificateHolder> store = signedData.getCertificates();
        List<X509CertificateHolder> certHolders = new ArrayList(store.getMatches(null));
        for (X509CertificateHolder certH : certHolders) {
            result.add(new JcaX509CertificateConverter().setProvider(ProviderBC).getCertificate(certH));
        }
        return result;
    }

    public static Boolean verify(String sig)  throws Exception  {
        CMSSignedData signedData = new CMSSignedData(Base64.decode(sig));
        //val content = signedData.signedContent as CMSProcessable
        Store<X509CertificateHolder> store = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        Iterator it = c.iterator();
        //println(String(content.content as ByteArray))
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation)(it.next());

            Collection<X509CertificateHolder> certCollection = store.getMatches((Selector<X509CertificateHolder>)signer.getSID());

            Iterator<X509CertificateHolder> certIt = certCollection.iterator();
            X509CertificateHolder certHolder = certIt.next();
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(ProviderBC).getCertificate(certHolder);
            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(ProviderBC).build(cert))) {
                System.out.println("verified");
                //println(JcaX509CertificateHolder(cert).getSubject().getRDNs(ROLE)[0].first.value)
                //println(cert.subjectDN)
            } else {
                return false;
            }
        }
        return true;
    }

    public static String GetContentFromSig(String sig) throws Exception {
        CMSSignedData signedData = new CMSSignedData(Base64.decode(sig));
        CMSProcessable content = signedData.getSignedContent();
        return (new String((byte[])(content.getContent())));
    }

    public static List<X509Certificate> ConvertCertificate(Certificate[] listCertificate){
        List<X509Certificate> result = new ArrayList<X509Certificate>();
        for (Certificate cert : listCertificate) {
            result.add((X509Certificate)cert);
        }
        return result;
    }

    public static X509Certificate GetCertificateFromBase64(String certString) throws Exception {
        ByteArrayInputStream encodedCert = new ByteArrayInputStream(Base64.decode(certString));
        CertificateFactory certFactory = CertificateFactory.getInstance(CertificateFactoryType, ProviderBC);
        return (X509Certificate)(certFactory.generateCertificate(encodedCert));
    }

    public static X500Name CreateDN(String email, String role) {
        return new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.EmailAddress, email)
                .addRDN(BCStyle.CN, OrgUrl)
                .addRDN(ROLE, role)
                .build();
    }
}
