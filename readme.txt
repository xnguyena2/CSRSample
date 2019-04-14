NodeCAIP : 18.212.26.64

1) user register with NodeCA and get certificate:
 - first user need create his keyPair in his device like android then send CSR to NodeCA sign to his CSR and send Certificate back and he can save his private key in local
   i create sample in file BaseFunctionKtTest in function registerTest
 - after register success with NodeCA now he use his key for sign his trasaction
 
        // load keystore from file user.jks with password 'user'
        val userKeyStore = LoadKeyStore("user.jks", "user")

        // get user key pair from key entry 'userkey' and password 'user'
        val userKeyPair = GetKeyPair(userKeyStore, "userkey", "user")

        //get user certChain in alias 'userkey'
        val userCerChainAsList = ConvertCertificate(userKeyStore.getCertificateChain("userkey"))

        //create signature digital for payload 'Paulo add 1.000USD to account'
        val sig = signData("Paulo add 1.000USD to account".toByteArray(), userKeyPair.private, userCerChainAsList)
    sig is signaturedigital of user then he can send this payload to cordapp.
 - Cordapp recive user request, and before start flow cordapp need validate user by check his signature.
   
        //get admin cert for validate later
        val adminCert = GetCertificateFromBase64(getRequest("http://$NodeCAIP:10050/GetAdminCert"))

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