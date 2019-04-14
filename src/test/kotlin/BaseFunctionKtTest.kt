import com.google.gson.Gson
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.Security
import java.security.cert.X509Certificate

internal class BaseFunctionKtTest{

    val NodeCAIP = "18.212.26.64"


    @Test
    fun registerTest(){
        //set bouncy castle provider --> must have this line because admin and user must use same provider
        //Security.insertProviderAt(BouncyCastleProvider(), 1)

        val email = "paulo@gm.com"

        //generate RSA for user
        val userKey = generateRSAKey()

        //Distinguished Name of user, role can be user, admin,...
        val userDN = CreateDN(email, "user")

        //create CSR for user then send to NodeCA and get back certificate
        val csr = GeneCSR(userKey, userDN)

        //send CSR to NodeCA
        val certString=getRequest("http://$NodeCAIP:10050/SignSCR?csr=${URLEncoder.encode(csr, "UTF-8")}")
        //println(certString)

        //get certificate chain from NodeCA
        val certChain = Gson().fromJson(certString, CertificateChainSigned::class.java)

        //certificate of user
        val userCert = GetCertificateFromBase64(certChain.UserCert)

        //certificate of intermedial admin
        val intermedialCert = GetCertificateFromBase64(certChain.IntermedialCert)

        //get admin certificate for validate certificate chains of user
        val adminCert = GetCertificateFromBase64(getRequest("http://$NodeCAIP:10050/GetAdminCert"))

        //create certificate chain of user, certchain must have userCert and intermedialCert
        val listTestCert = ArrayList<X509Certificate>()
        listTestCert.add(intermedialCert)
        listTestCert.add(userCert)

        //check again cert chain is validate
        var resutlValid = validateCertificateChain(adminCert, listTestCert)
        System.out.println(resutlValid.toString())

        //save to file user.jks with key save in entry name 'userkey' and password protect this file is 'user'
        SaveKeyStore("userkey", userKey, listTestCert.toTypedArray(), "user", "user.jks")
    }

    @Test
    fun signatureDigitalTest() {

        //set bouncy castle provider --> must have this line because admin and user must use same provider
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        // load keystore from file user.jks with password 'user'
        val userKeyStore = LoadKeyStore("user.jks", "user")

        // get user key pair from key entry 'userkey' and password 'user'
        val userKeyPair = GetKeyPair(userKeyStore, "userkey", "user")

        //get user certChain in alias 'userkey'
        val userCerChainAsList = ConvertCertificate(userKeyStore.getCertificateChain("userkey"))

        //get admin cert for validate later
        val adminCert = GetCertificateFromBase64(getRequest("http://$NodeCAIP:10050/GetAdminCert"))

        //create signature digital for payload 'Paulo add 1.000USD to account'
        val sig = signData("Paulo add 1.000USD to account".toByteArray(), userKeyPair.private, userCerChainAsList)

        //extract user certChain by function GetListCertificateFromSignature(sig) then validate this certChain by adminCert
        validateCertificateChain(adminCert, GetListCertificateFromSignature(sig))

        //verify signature , check for sure the content did not change when send through in internet
        if (verify(sig)) {
            println("verify sig success!")
        } else {
            println("verify sig Fail!")
        }

        //Get content from signature
        println(GetContentFromSig(sig))
    }


    //run http GET
    fun getRequest(requestUrl: String): String {
        val urlObj = URL(requestUrl)
        val con = urlObj.openConnection() as HttpURLConnection
        con.requestMethod = "GET"
        println("Response Code : ${con.responseCode}")
        val inStream = BufferedReader(InputStreamReader(con.inputStream))
        return inStream.use { bufferedReader -> bufferedReader.readText() }
    }
}