package com.dotc.plugins;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;

import android.util.Base64;


public class Encryptor extends CordovaPlugin 
{
	private String RAW_KEY     = "TYM15QKCuQgCWLzX72dgPEBPMtaqd0KzKmbbTEqRYd74TDU/gPwmE8Mc1qFjgDFV9GpQoGxYIMetqWqhanneHcWBpSF7X7AFAViziS7jvwQxLDftSEC6OBtjS5+bbWvK4+CzrJvkk7VCOtk+EzUNhJYyKIvO01SD+vkzqZAh4wY=";
	//private String PUBLIC_KEY  = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC83VssqxOMSajp2iqI1dViWofi\n4uqJuguF4OD8T03olArMEYyUPZCBXa9TNP8oKHqyZqXdL39qZJYcfeII5Mvwuzml\nGpoZtXqNldbJ//QR7DWwWXazEYVSoZCsap2KWosAGFnpRVj+palQeTf4Rg7lnFPw\nktVVYxK2Y06khj7/IwIDAQAB\n-----END PUBLIC KEY-----";
	//"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7Ti9AWgEuDOavqOAUhNL84M1e\n/x00rk1ALygEWXV1do+n4j9ZTPfAcbfV76TD9z9RIjRbUWj8skg5RRd5V9FCENG/\n5EVdz0qsi70NMxhXX4H4FMAKPxUtzTBh/U/d8Rb0pgUmdXHi9e4VhQhwryFMxPTf\nKSHrB1bsW/zoxnAaEQIDAQAB\n-----END PUBLIC KEY-----";
	private String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALzdWyyrE4xJqOna\nKojV1WJah+Li6om6C4Xg4PxPTeiUCswRjJQ9kIFdr1M0/ygoerJmpd0vf2pklhx9\n4gjky/C7OaUamhm1eo2V1sn/9BHsNbBZdrMRhVKhkKxqnYpaiwAYWelFWP6lqVB5\nN/hGDuWcU/CS1VVjErZjTqSGPv8jAgMBAAECgYB565/HBy1YW9jKFgdtTDUzB+Q+\n6GOlw09a/p/e4UcXBDKwKAgLTm7xxEvBOC4be34xmqgqUFY9lW9+NxlqymCICdCN\nPLOzv0agNQVEW2ntmQA+NZKJx6vXX4qnp7MwSteBMFnqsWuFkn0m7t8vTUvbb/vx\nbShFoA3rExeaOrDkCQJBAPqiag2zUqL7PL4F4fAkEcKCLkrUbeI6dUQ6NSx/n/RY\nr0F7ZmnBbFKoCMqOiRO8XKYRSBfHu+qBPUxRmvFkPacCQQDA6GqusZYn8iYedvlg\nKYBDXtv1Ro8dXAsSVExgCi1iOOYqv2P7xq3A3mfOkvvsBVTxQP9nHeueEz39Um7w\nq/olAkEAkby3JlhLiPHGFEifZF/U4+GGwYRckNulLJMcME/V1uNqpQz4NC6Aql+D\nHSVcl9lDll0eKpW9s1KLLkGVcx/yqQJAHil43L2pk69Z5HOHxFBY3K/NRol0wQtu\nM7x4gJ+2vt/UpSRttqU276wWoQb8WsfuoxYdmPrlpz6s95nW/Mx2/QJBAMDM7MlF\nleNWIyblS+udwzoReiEVtofnqillTiETZVDQNpsQfn+amSsxEfZuC4GRmOnPWm9w\nChw4/cSs1b833Oc=\n-----END PRIVATE KEY-----";
	public void initialize(CordovaInterface cordova, CordovaWebView webView) 
	{
//		PUBLIC_KEY = PUBLIC_KEY.replaceAll("-----BEGIN PUBLIC KEY-----", "");
//		PUBLIC_KEY = PUBLIC_KEY.replaceAll("-----END PUBLIC KEY-----", "");
//		PUBLIC_KEY = PUBLIC_KEY.replaceAll("\n", "");
		
		PRIVATE_KEY = PRIVATE_KEY.replaceAll("-----BEGIN PRIVATE KEY-----", "");
		PRIVATE_KEY = PRIVATE_KEY.replaceAll("-----END PRIVATE KEY-----", "");
		PRIVATE_KEY = PRIVATE_KEY.replaceAll("\n", "");
		
		super.initialize(cordova, webView);
	}
	
	@Override
	public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException 
	{
		if("encrypt".equals(action)) 
		{
			try
			{
				String srcData = args.getString(0);
//				Cipher rsa = Cipher.getInstance("RSA/None/PKCS1Padding");
//				
//				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(PUBLIC_KEY.getBytes(), Base64.DEFAULT));
//		        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(keySpec);
//				
//				//X509EncodedKeySpec spec = new X509EncodedKeySpec(PUBLIC_KEY.getBytes());
//		        //PublicKey  key = KeyFactory.getInstance("RSA").generatePublic(spec); 
//	
//				rsa.init(Cipher.ENCRYPT_MODE, key);
//				String dstData = Base64.encodeToString(rsa.doFinal(srcData.getBytes()), Base64.DEFAULT);
				
                SecretKeySpec key = new SecretKeySpec(key(), "AES");  
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");  
                cipher.init(Cipher.ENCRYPT_MODE, key);
                
				String dstData = Base64.encodeToString(cipher.doFinal(srcData.getBytes()), Base64.DEFAULT);
				
				callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, dstData));
			}
			catch(Exception e)
			{
				callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR));
			}
			return true;
		}
		else if("decrypt".equals(action))
		{
			try
			{
				byte[] srcData = Base64.decode(args.getString(0).getBytes(), Base64.DEFAULT);
			
//				Cipher rsa = Cipher.getInstance("RSA/None/PKCS1Padding");
//				
//				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decode(PRIVATE_KEY.getBytes(), Base64.DEFAULT));
//		        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(spec); 
//	
//				rsa.init(Cipher.DECRYPT_MODE, key);
//				String dstData = new String(rsa.doFinal(srcData));
				
				SecretKeySpec key = new SecretKeySpec(key(), "AES"); 
               
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");  
                cipher.init(Cipher.DECRYPT_MODE, key);
                
                String dstData = new String(cipher.doFinal(srcData));
				
				
				callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, dstData));
			}
			catch(Exception e)
			{
				callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR));
			}
			
			return true;
		}
		
		return false;
	}
	
	private byte[] key() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException
	{
		byte[] srcData = Base64.decode(RAW_KEY.getBytes(), Base64.DEFAULT);
		
		Cipher rsa = Cipher.getInstance("RSA/None/PKCS1Padding");
		
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decode(PRIVATE_KEY.getBytes(), Base64.DEFAULT));
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(spec); 

		rsa.init(Cipher.DECRYPT_MODE, key);
		return rsa.doFinal(srcData);
	}
	

}
