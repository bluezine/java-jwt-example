package kr.co.bluezine.jwt;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

/**
 * JWT Util
 * @author Kisig Ian Seo
 */
public class JWTUtil
{
	/**
	 * Singleton instance
	 */
	private static JWTUtil instance;

	/**
	 * Encrypt key
	 */
	private final String ENCKEY = "testtoken";

	/**
	 * Encrypt key byte
	 */
	private byte[] keyByte;

	/**
	 * Singleton block
	 */
	private JWTUtil()
	{
		keyByte = Arrays.copyOf(ENCKEY.getBytes(), 256);
	}

	/**
	 * Get instance
	 * @return
	 */
	public static JWTUtil getInstance()
	{
		if (instance == null)
			instance = new JWTUtil();
		return instance;
	}

	/**
	 * Get claimset
	 * @param token
	 * @return
	 * @throws ParseException
	 * @throws JOSEException
	 * @throws InvalidJWTTokenException
	 */
	public JWTClaimsSet getClaimsSet(String token) throws ParseException, JOSEException, InvalidJWTTokenException
	{
		SignedJWT signedJWT = SignedJWT.parse(token);
		if (signedJWT.verify(new MACVerifier(keyByte)))
		{
			JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
			return claimsSet;
		}
		else
		{
			throw new InvalidJWTTokenException();
		}
	}

	/**
	 * Make token
	 * @param attributes
	 * @param expireDate
	 * @return
	 * @throws KeyLengthException
	 * @throws JOSEException
	 */
	public String makeJWT(Map<String, Object> attributes, Date expireDate) throws KeyLengthException, JOSEException
	{
		Builder builder = new JWTClaimsSet.Builder();
		builder.expirationTime(expireDate);

		attributes.entrySet().stream().forEach(item -> {
			builder.claim(item.getKey(), item.getValue());
		});

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), builder.build());
		signedJWT.sign(new MACSigner(keyByte));

		return signedJWT.serialize();
	}

	/**
	 * Invalid token exception
	 * @author Kisig Ian Seo
	 */
	public static class InvalidJWTTokenException extends Exception
	{
		private static final long serialVersionUID = -2245081780506876377L;
	}
}
