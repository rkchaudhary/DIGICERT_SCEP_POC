package com.rkc.scep;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.CachingCertificateVerifier;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.transaction.TransactionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SCEPSampleTest {
    private static final Logger logger = LoggerFactory.getLogger(SCEPSampleTest.class);
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            URL url = new URL(" https://demo.one.digicert.com/mpki/api/v1/scep/695bbdfc-1f00-47d9-a97b-58e9415f3b04/cgi-bin/pkiclient.exe");
            
            //Callback handler
            CertificateVerifier consoleVerifier = new OptimisticCertificateVerifier();
            CertificateVerifier verifier = new CachingCertificateVerifier(consoleVerifier);
            CallbackHandler handler = new DefaultCallbackHandler(verifier);       

            Client client = new Client(url, handler);

    //Step 2 Start : Generating private self signed certificate 

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair requesterKeyPair = keyPairGenerator.genKeyPair();     
//2024-05-06 14:43:44 DEBUG AbstractCertStoreInspector:52 - Using [dn=CN=IBM TEST INTERMEDIATE CA, O=IBM, 
//STREET=New Orchard Road, OID.2.5.4.17=10504, L=Armonk, ST=New York, C=US; 
//serial=90844453212198651870623446059612023017552427855] for message signing entity

            X500Principal requesterIssuer = new X500Principal("CN=IBM TEST INTERMEDIATE CA, O=IBM, STREET=New Orchard Road, OID.2.5.4.17=10504, L=Armonk, ST=New York, C=US");
            BigInteger serial = BigInteger.ONE;
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.DATE, -1); // yesterday
            Date notBefore = calendar.getTime();
            calendar.add(Calendar.DATE, +2); // tomorrow
            Date notAfter = calendar.getTime();

            X500Principal requesterSubject = new X500Principal("CN=IBM TEST INTERMEDIATE CA, O=IBM, STREET=New Orchard Road, OID.2.5.4.17=10504, L=Armonk, ST=New York, C=US");
            PublicKey requesterPubKey = requesterKeyPair.getPublic(); // from generated key pair
            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(requesterIssuer, serial, notBefore, notAfter, requesterSubject, requesterPubKey);

            // Signing
            PrivateKey requesterPrivKey = requesterKeyPair.getPrivate(); // from generated key pair
            JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder("SHA512withRSA"); // from above
            ContentSigner certSigner = certSignerBuilder.build(requesterPrivKey);

            X509CertificateHolder certHolder = certBuilder.build(certSigner);

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            X509Certificate requesterCert = converter.getCertificate(certHolder);

    // End of step 2 : Selft Signed Certificate  
            
            X500Principal entitySubject = requesterSubject; // use the same subject as the self-signed certificate
            PublicKey entityPubKey = requesterKeyPair.getPublic();
            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(entitySubject, entityPubKey); 

            DERPrintableString password = new DERPrintableString("uKXw.wb.iaUCzbRFK*p9pL8DjeqRpfphM3Ze92iLPw@4VD@oF6pnb@tDZHkW9m@a");
            //DERPrintableString password = new DERPrintableString("\\x75\\x4B\\x58\\x77\\x2E\\x77\\x62\\x2E\\x69\\x61\\x55\\x43\\x7A\\x62\\x52\\x46\\x4B\\x2A\\x70\\x39\\x70\\x4C\\x38\\x44\\x6A\\x65\\x71\\x52\\x70\\x66\\x70\\x68\\x4D\\x33\\x5A\\x65\\x39\\x32\\x69\\x4C\\x50\\x77\\x40\\x34\\x56\\x44\\x40\\x6F\\x46\\x36\\x70\\x6E\\x62\\x40\\x74\\x44\\x5A\\x48\\x6B\\x57\\x39\\x6D\\x40\\x61");
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);

            PrivateKey entityPrivKey = requesterKeyPair.getPrivate();
            JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
            ContentSigner csrSigner = csrSignerBuilder.build(entityPrivKey);
            PKCS10CertificationRequest csr = csrBuilder.build(csrSigner); 
            
            EnrollmentResponse res = client.enrol(requesterCert, requesterPrivKey, csr, "Mobile PoC Rajiv with global enrollment");
            //EnrollmentResponse res = client.enrol(requesterCert, requesterPrivKey, csr);

            System.out.println(res.isSuccess());

        } catch (MalformedURLException e) {
            logger.error("MalformedURLException Error connecting to server", e);
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            logger.error("NoSuchAlgorithmException Error connecting to server", e);
            e.printStackTrace();
        } catch (ClientException e) {
            logger.error("ClientException Error connecting to server", e);
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            logger.error("OperatorCreationException Error connecting to server", e);
            e.printStackTrace();
        } catch (CertificateException e) {
            logger.error("CertificateException Error connecting to server", e);
            e.printStackTrace();
        } catch (TransactionException e) {
        logger.error("TransactionException Error connecting to server", e);
            e.printStackTrace();
        }
        
    }
}
