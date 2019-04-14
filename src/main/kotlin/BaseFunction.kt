import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.*
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.Selector
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import sun.misc.BASE64Encoder
import java.io.*
import java.math.BigInteger
import java.security.*
import java.security.cert.*
import java.security.cert.Certificate
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.*
import kotlin.collections.ArrayList

val ROLE = ASN1ObjectIdentifier("2.5.4.120").intern()!!
val ProviderBC = BouncyCastleProvider()
val SignatureAlgorithm = "SHA256withRSA"//SHA256withECDSA
val OrgUrl = "multiledgers.com"
val CertificateFactoryType = "X.509"
val KeyPairGeneratorAlgorithm = "RSA"
val KeyStoreType = "JKS"
val CertPathValidatorAlgorithm = "PKIX"
val NotBeforeDate = Date.from(LocalDate.of(2018, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant())
val NotAfterDate = Date.from(LocalDate.of(2020, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant())

class CertificateChainSigned(val UserCert: String, val IntermedialCert: String)


fun X509CertificateHolder.convertCa(): X509Certificate {
    val converter = JcaX509CertificateConverter()
    converter.setProvider(ProviderBC)
    return converter.getCertificate(this)
}

class X509CertificateFactory {
    private val delegate: CertificateFactory = CertificateFactory.getInstance(CertificateFactoryType,ProviderBC)

    fun generateCertPath(certificates: List<X509Certificate>): CertPath = delegate.generateCertPath(certificates)
}

class PemFile {
    private var pemObject: PemObject

    constructor(key: Key, description: String) {
        pemObject = PemObject(description, key.encoded)
    }

    @Throws(IOException::class, FileNotFoundException::class)
    fun write(fileName: String) {
        val pemWriter = PemWriter(OutputStreamWriter(FileOutputStream(fileName)))
        pemWriter.use { pemWriter ->
            pemWriter.writeObject(pemObject)
        }
    }
}

@Throws(Exception::class)
fun generateRSAKey(): KeyPair {
    val gen: KeyPairGenerator = KeyPairGenerator.getInstance(KeyPairGeneratorAlgorithm, ProviderBC)

    return gen.generateKeyPair()
}

fun generateCertificate(subjectPublicKey: PublicKey, subjectDN: X500Name, issuerDN: X500Name, issuerKeyPair: KeyPair): X509Certificate {
    val random = SecureRandom()
    val id = ByteArray(20)
    random.nextBytes(id)
    val serial = BigInteger(160, random)
    val usage = KeyUsage(KeyUsage.keyCertSign or KeyUsage.digitalSignature)
    val constraints = BasicConstraints(true)
    val usageEx = ExtendedKeyUsage(arrayOf(
            KeyPurposeId.id_kp_serverAuth,
            KeyPurposeId.id_kp_clientAuth)
    )
    val signer = JcaContentSignerBuilder(SignatureAlgorithm)
            .build(issuerKeyPair.private)
    val certificate = JcaX509v3CertificateBuilder(
            issuerDN,
            serial,
            NotBeforeDate,
            NotAfterDate,
            subjectDN,
            subjectPublicKey)
    certificate.addExtension(
            Extension.basicConstraints,
            true,
            constraints.encoded
    )
    certificate.addExtension(Extension.keyUsage, false, usage.encoded)
    certificate.addExtension(
            Extension.extendedKeyUsage,
            false,
            usageEx.encoded
    )

    // build BouncyCastle certificate
    return certificate.build(signer).run {
        require(isValidOn(Date()))
        require(isSignatureValid(JcaContentVerifierProviderBuilder().build(issuerKeyPair.public)))
        convertCa()
    }
}

@Throws(IOException::class, FileNotFoundException::class)
fun SaveKeyPemFile(key: Key, description: String, fileName: String) {
    val pemFile = PemFile(key, description)
    pemFile.write(fileName)
}

@Throws(IOException::class, FileNotFoundException::class)
fun GeneCSR(keyPair: KeyPair, subjectDN: X500Name): String {
    val signGen: ContentSigner = JcaContentSignerBuilder(SignatureAlgorithm).setProvider(ProviderBC).build(keyPair.private)
    val builder: PKCS10CertificationRequestBuilder = JcaPKCS10CertificationRequestBuilder(subjectDN, keyPair.public)
    val request: PKCS10CertificationRequest = builder.build(signGen)
    return Base64.toBase64String(request.encoded)
}

fun SaveKeyStore(keyEntry: String, keyPair: KeyPair, certChain: Array<X509Certificate?>, pwd: String, fileName: String) {
    val keyStore = KeyStore.getInstance(KeyStoreType)
    keyStore.load(null,null)
    keyStore.setKeyEntry(keyEntry, keyPair.private, pwd.toCharArray(), certChain)
    val fileSave = FileOutputStream(fileName)
    keyStore.store(fileSave, pwd.toCharArray())
    fileSave.close()
}

fun LoadKeyStore(fileName: String, pwd: String ): KeyStore {
    val keyStore = KeyStore.getInstance(KeyStoreType)
    keyStore.load(FileInputStream(fileName), pwd.toCharArray())
    return keyStore
}

fun GetKeyPair(keyStore: KeyStore, keyEntry: String, pwd: String):KeyPair {
    val privateKey = keyStore.getKey(keyEntry, pwd.toCharArray()) as PrivateKey
    val cer = keyStore.getCertificate(keyEntry) as X509Certificate
    return KeyPair(cer.publicKey, privateKey)
}

fun validateCertificateChain(trustedRoot: X509Certificate, certificates: List<X509Certificate>) : CertPathValidatorResult {
    require(certificates.isNotEmpty()) { "Certificate path must contain at least one certificate" }
    return validateCertPath(trustedRoot, buildCertPath(certificates))
}

fun validateCertPath(trustedRoot: X509Certificate, certPath: CertPath) : CertPathValidatorResult {
    val params = PKIXParameters(setOf(TrustAnchor(trustedRoot, null)))
    params.isRevocationEnabled = false
    return CertPathValidator.getInstance(CertPathValidatorAlgorithm, ProviderBC).validate(certPath, params)
}

fun buildCertPath(certificates: List<X509Certificate>): CertPath {
    return X509CertificateFactory().generateCertPath(certificates)
}

fun signCSR(pemCSR: String, rootKeyPair: KeyPair, rootCACert: X509Certificate): X509Certificate {
    val csr = PKCS10CertificationRequest(Base64.decode(pemCSR))
    val jcaPKCS10CertificationRequest = JcaPKCS10CertificationRequest(csr)
    return generateCertificate(jcaPKCS10CertificationRequest.publicKey, jcaPKCS10CertificationRequest.subject,
            X500Name.getInstance(rootCACert.subjectX500Principal.encoded), rootKeyPair)
}

fun signData(datas: ByteArray, privateKey: PrivateKey, listCertificate: List<X509Certificate>): String {
    val msg = CMSProcessableByteArray(datas)
    val certs = JcaCertStore(listCertificate)
    val gen = CMSSignedDataGenerator()
    val sha1Signer = JcaContentSignerBuilder(SignatureAlgorithm).setProvider(ProviderBC).build(privateKey)
    gen.addSignerInfoGenerator(JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().setProvider(ProviderBC).build()).build(sha1Signer, listCertificate.last()))
    gen.addCertificates(certs)
    val sigData = gen.generate(msg, true)
    val encoder = BASE64Encoder()
    return encoder.encode(sigData.encoded)
}

fun GetListCertificateFromSignature(sig: String): ArrayList<X509Certificate> {
    val result = ArrayList<X509Certificate>()
    val signedData = CMSSignedData(Base64.decode(sig))
    val store = signedData.certificates
    val certHolders = ArrayList(store.getMatches(null))
    for (certH in certHolders) {
        result.add(JcaX509CertificateConverter().setProvider(ProviderBC).getCertificate(certH))
    }
    return result
}

fun verify(sig: String) : Boolean {
    val signedData = CMSSignedData(Base64.decode(sig))
    //val content = signedData.signedContent as CMSProcessable
    val store = signedData.certificates
    val signers = signedData.signerInfos
    val c = signers.signers
    val it = c.iterator()
    //println(String(content.content as ByteArray))
    while (it.hasNext()) {
        val signer = it.next() as SignerInformation

        val certCollection = store.getMatches(signer.sid as Selector<X509CertificateHolder>)

        val certIt = certCollection.iterator()
        val certHolder = certIt.next() as X509CertificateHolder
        val cert = JcaX509CertificateConverter().setProvider(ProviderBC).getCertificate(certHolder)
        if (signer.verify(JcaSimpleSignerInfoVerifierBuilder().setProvider(ProviderBC).build(cert))) {
            //println("verified")
            //println(JcaX509CertificateHolder(cert).getSubject().getRDNs(ROLE)[0].first.value)
            //println(cert.subjectDN)
        } else {
            return false
        }
    }
    return true
}

fun GetContentFromSig(sig: String):String{
    val signedData = CMSSignedData(Base64.decode(sig))
    val content = signedData.signedContent as CMSProcessable
    return (String(content.content as ByteArray))
}

fun ConvertCertificate(listCertificate: Array<Certificate>) : List<X509Certificate> {
    val result = ArrayList<X509Certificate>()
    for (cert in listCertificate) {
        result.add(cert as X509Certificate)
    }
    return result
}

fun GetCertificateFromBase64(certString:String): X509Certificate {
    val encodedCert = ByteArrayInputStream(Base64.decode(certString))
    val certFactory = CertificateFactory.getInstance(CertificateFactoryType, ProviderBC)
    return certFactory.generateCertificate(encodedCert) as X509Certificate
}

fun CreateDN(email:String, role:String):X500Name {
    return X500NameBuilder(BCStyle.INSTANCE)
        .addRDN(BCStyle.EmailAddress, email)
        .addRDN(BCStyle.CN, OrgUrl)
        .addRDN(ROLE, role)
        .build()
}