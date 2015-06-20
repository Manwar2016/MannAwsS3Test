
import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.Request;
import com.amazonaws.SDKGlobalConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.event.ProgressInputStream;
import com.amazonaws.internal.SdkDigestInputStream;
import com.amazonaws.util.Base64;
import com.amazonaws.util.BinaryUtils;
import com.amazonaws.util.HttpUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac; 
import javax.crypto.spec.SecretKeySpec;

import java.util.SimpleTimeZone;


import com.amazonaws.auth.profile.ProfileCredentialsProvider;


public class S3SignatureV4 {
	

		static byte[] HmacSHA256(String data, byte[] key) throws Exception  {
		     String algorithm="HmacSHA256";
		     Mac mac = Mac.getInstance(algorithm);
		     mac.init(new SecretKeySpec(key, algorithm));
		     return mac.doFinal(data.getBytes("UTF8"));
		}

		static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception  {
		     byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
		     byte[] kDate    = HmacSHA256(dateStamp, kSecret);
		     byte[] kRegion  = HmacSHA256(regionName, kDate);
		     byte[] kService = HmacSHA256(serviceName, kRegion);
		     byte[] kSigning = HmacSHA256("aws4_request", kService);
			 byte[] signature = HmacSHA256("<BASE64 encoded policy>", kSigning);
				return signature;

		}
		
		public static void main(String[] args) throws Exception {
			String SecretKey = new ProfileCredentialsProvider().getCredentials().getAWSSecretKey().toString();
			SimpleDateFormat dateTimeFormat;
			dateTimeFormat = new SimpleDateFormat("yyyyMMdd");
	        dateTimeFormat.setTimeZone(new SimpleTimeZone(0, "UTC"));
	        Date now = new Date();
			String dateStamp = dateTimeFormat.format(now);
			byte[] Sign = getSignatureKey(SecretKey, dateStamp, "cn-north-1", "s3");
			System.out.println(BinaryUtils.toHex(Sign));

			
		}
}
