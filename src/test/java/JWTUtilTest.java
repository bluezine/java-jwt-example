import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jwt.JWTClaimsSet;

import kr.co.bluezine.jwt.JWTUtil;
import kr.co.bluezine.jwt.JWTUtil.InvalidJWTTokenException;

/**
 * JWTUtil Test
 * @author Kisig Ian Seo
 */
public class JWTUtilTest
{
	@Test
	public void test() throws KeyLengthException, JOSEException, ParseException, InvalidJWTTokenException
	{
		JWTUtil util = JWTUtil.getInstance();
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("A", "FFF");

		String token = util.makeJWT(attributes, new Date(new Date().getTime() + 1000000));
		token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MjM2NjczMjUsIkEiOiJGRkYifQ.2y7aEalQcI_xMnKGbrcIxxEkOsKKaGj07yumwwKgkb4";
		System.out.println(token);

		JWTClaimsSet claimsSet = util.getClaimsSet(token);
		System.out.println(claimsSet.getExpirationTime());
		System.out.println(claimsSet.getAudience());
		claimsSet.getClaims().entrySet().forEach(claim -> {
			System.out.println(claim.getKey() + "-" + claim.getValue());
		});
		System.out.println(claimsSet.getClaims());
	}
}
