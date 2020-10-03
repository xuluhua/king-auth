package com.auth.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

@Component
public class EncryptionUtil {

	private static final String CHARSET = "UTF-8";

	private static final String RSA_ALGORITHM = "RSA";

	private static final String RSAPUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgpCzAKgghCG_aNtjB6SKua22nN1ik03fXw8lhGsXJbzBfThlB97YZYFjYslGaHUz9-_CMMlf1vP37a4Gm_uYNq0ikSy6uhkjUtwtckwZ-Ybq2Eo_xvcpUDF44FcuepFW45YFhq80R_effLhH1tQqIpxWp-CfZUbOpL5L56M4TuwIDAQAB";

	private static final String RSAPRIVATEKEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKCkLMAqCCEIb9o22MHpIq5rbac3WKTTd9fDyWEaxclvMF9OGUH3thlgWNiyUZodTP378IwyV_W8_ftrgab-5g2rSKRLLq6GSNS3C1yTBn5hurYSj_G9ylQMXjgVy56kVbjlgWGrzRH9598uEfW1CoinFan4J9lRs6kvkvnozhO7AgMBAAECgYApwMJI6CPYwiKgayUHsZrsDswfbElD_hrmH-NVs-m4o4fFHb1-4e2YxuwQ1rhTAE6krTkml2c5Xff9w0GdsB8HAQSfdAhds25chOdv4FvrGeThDrDBz3-7jWGzX8kykah_rl7JmF4wiE7NLE6xWXu1SLcu2YQuqU9vC3kwPIgLkQJBANH7wlKal-YrF70EYExouKAs5D-mZUxnxpxRTI_qOivWRUl5QK7AOqTB_M9r1OQk6l-hRYBEHASlD9R4yE-LbNcCQQDD2EhOmxiFqiM-UZOWqZ-ORrBvuajQOS1yfxExWZ4EnCqd42Yp3oJO2Se50MFCrco3hGO8hodD41dGmX3jju-9AkEAhHpEkB7uhI1dbagMJUjQamXIHwwYzsqOOGLmXcmVp8CIeCFimJ24oeetWyOZ7dIIeArkMVdHIfsNcKw_HEhHgwJAcIWVlcQ6pKGKOkX4fDnc-IvY13hea7ROTlh_clFBHvjy62A51JiJWfAeiP5N65eadadU_n50vSajgGa0E8iOKQJAY2FTM5YxoV_qvQDIc_DRu535bNK8pFx8q6FVHs8j0pjbMKjZJz0IgRtLIdRke4lEYRuX6WiHicp_2VpFuMNRMw";

	public static Map<String, String> createKeys(int keySize) {
		// 为RSA算法创建一个KeyPairGenerator对象
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("No such algorithm-->[\" + RSA_ALGORITHM + \"]");
		}
		// 初始化KeyPairGenerator对象,密钥长度
		keyPairGenerator.initialize(keySize);
		// 生成密匙对
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// 得到公钥
		Key publicKey = keyPair.getPublic();
		String publicKeyString = Base64.encodeBase64URLSafeString(publicKey.getEncoded());
		// 得到私钥
		Key privateKey = keyPair.getPrivate();
		String privateKeyString = Base64.encodeBase64URLSafeString(privateKey.getEncoded());

		Map<String, String> keyPairMap = new HashMap<String, String>();
		keyPairMap.put("publicKey", publicKeyString);
		keyPairMap.put("privateKey", privateKeyString);

		return keyPairMap;
	}

	/**
	 * 得到公钥
	 * 
	 * @param publicKey 密钥字符串（经过base64编码）
	 * @throws Exception
	 */
	public static RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		// 通过X509编码的Key指令获得公钥对象
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
		RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
		return key;
	}

	/**
	 * 得到私钥
	 * 
	 * @param privateKey 密钥字符串（经过base64编码）
	 * @throws Exception
	 */
	public static RSAPrivateKey getPrivateKey(String privateKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		// 通过PKCS#8编码的Key指令获得私钥对象
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
		RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
		return key;
	}

	/**
	 * 公钥加密
	 * 
	 * @param data
	 * @param publicKey
	 * @return
	 */
	public static String publicEncrypt(String data) {
		try {
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(RSAPUBLICKEY));
			return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET),
					getPublicKey(RSAPUBLICKEY).getModulus().bitLength()));
		} catch (Exception e) {
			throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
		}
	}

	/**
	 * 私钥解密
	 * 
	 * @param data
	 * @param privateKey
	 * @return
	 */

	public static String privateDecrypt(String data) {
		try {
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(RSAPRIVATEKEY));
			return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data),
					getPrivateKey(RSAPRIVATEKEY).getModulus().bitLength()), CHARSET);
		} catch (Exception e) {
			throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
		}
	}

	/**
	 * 私钥加密
	 * 
	 * @param data
	 * @param privateKey
	 * @return
	 */

	public static String privateEncrypt(String data) {
		try {
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey(RSAPRIVATEKEY));
			return Base64.encodeBase64URLSafeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET),
					getPrivateKey(RSAPRIVATEKEY).getModulus().bitLength()));
		} catch (Exception e) {
			throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
		}
	}

	/**
	 * 公钥解密
	 * 
	 * @param data
	 * @param publicKey
	 * @return
	 */

	public static String publicDecrypt(String data) {
		try {
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, getPublicKey(RSAPUBLICKEY));
			return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data),
					getPublicKey(RSAPUBLICKEY).getModulus().bitLength()), CHARSET);
		} catch (Exception e) {
			throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
		}
	}

	private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize) {
		int maxBlock = 0;
		if (opmode == Cipher.DECRYPT_MODE) {
			maxBlock = keySize / 8;
		} else {
			maxBlock = keySize / 8 - 11;
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] buff;
		int i = 0;
		try {
			while (datas.length > offSet) {
				if (datas.length - offSet > maxBlock) {
					buff = cipher.doFinal(datas, offSet, maxBlock);
				} else {
					buff = cipher.doFinal(datas, offSet, datas.length - offSet);
				}
				out.write(buff, 0, buff.length);
				i++;
				offSet = i * maxBlock;
			}
		} catch (Exception e) {
			throw new RuntimeException("加解密阀值为[" + maxBlock + "]的数据时发生异常", e);
		}
		byte[] resultDatas = out.toByteArray();
		IOUtils.closeQuietly(out);
		return resultDatas;
	}

	public static void main(String[] args) {
		String password = "xuluhua1314";
		System.out.println("\r明文：\r\n" + password);
		System.out.println("\r明文大小：\r\n" + password.getBytes().length);
		String encodedData = publicEncrypt(password);
		System.out.println("密文：\r\n" + encodedData);
		String decodedData = privateDecrypt(encodedData);
		System.out.println("解密后文字: \r\n" + decodedData);
	}

}
