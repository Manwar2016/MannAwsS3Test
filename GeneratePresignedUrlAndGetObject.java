package aws;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.HttpMethod;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;

public class GeneratePreSignedUrlAndGetObject {
private static String bucketName = "pingpublic";
private static String objectKey = "dig.txt";
public static void main(String[] args) throws IOException {
	AmazonS3 s3client = new AmazonS3Client(new ProfileCredentialsProvider());
	Region s3region = Region.getRegion(Regions.CN_NORTH_1);
	s3client.setRegion(s3region);

try {
System.out.println("Generating pre-signed URL.");
java.util.Date expiration = new java.util.Date();
long milliSeconds = expiration.getTime();
milliSeconds += 1000 * 60 * 60; // Add 1 hour.
expiration.setTime(milliSeconds);
GeneratePresignedUrlRequest generatePresignedUrlRequest =
new GeneratePresignedUrlRequest(bucketName, objectKey);
generatePresignedUrlRequest.setMethod(HttpMethod.GET);
generatePresignedUrlRequest.setExpiration(expiration);
URL url = s3client.generatePresignedUrl(generatePresignedUrlRequest);
System.out.println("Pre-Signed URL = " + url.toString());
} catch (AmazonServiceException exception) {
System.out.println("Caught an AmazonServiceException, " +
"which means your request made it " +
"to Amazon S3, but was rejected with an error response " +
"for some reason.");
System.out.println("Error Message: " + exception.getMessage());
System.out.println("HTTP Code: " + exception.getStatusCode());
System.out.println("AWS Error Code:" + exception.getErrorCode());
System.out.println("Error Type: " + exception.getErrorType());
System.out.println("Request ID: " + exception.getRequestId());
} catch (AmazonClientException ace) {
System.out.println("Caught an AmazonClientException, " +
"which means the client encountered " +
"an internal error while trying to communicate" +
" with S3, " +
"such as not being able to access the network.");
System.out.println("Error Message: " + ace.getMessage());
}
}
}
