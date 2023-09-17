package com.springboot.cognito.service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.SimpleTimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserResult;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminSetUserPasswordRequest;
import com.amazonaws.services.cognitoidp.model.AdminUpdateUserAttributesRequest;
import com.amazonaws.services.cognitoidp.model.AdminUpdateUserAttributesResult;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.amazonaws.services.cognitoidp.model.CodeMismatchException;
import com.amazonaws.services.cognitoidp.model.DeliveryMediumType;
import com.amazonaws.services.cognitoidp.model.ExpiredCodeException;
import com.amazonaws.services.cognitoidp.model.GetUserAttributeVerificationCodeRequest;
import com.amazonaws.services.cognitoidp.model.GetUserAttributeVerificationCodeResult;
import com.amazonaws.services.cognitoidp.model.InitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.InitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.NotAuthorizedException;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.UpdateUserAttributesRequest;
import com.amazonaws.services.cognitoidp.model.UpdateUserAttributesResult;
import com.amazonaws.services.cognitoidp.model.VerifyUserAttributeRequest;
import com.amazonaws.services.cognitoidp.model.VerifyUserAttributeResult;
import com.springboot.cognito.dto.EnableMFADto;
import com.springboot.cognito.dto.LoginRequestDTO;
import com.springboot.cognito.dto.OtpVerificaitonRequestDto;
import com.springboot.cognito.dto.OutputResponseDTO;
import com.springboot.cognito.dto.SignUpDto;
import com.springboot.cognito.dto.UserSignInResponse;
import com.springboot.cognito.dto.VerifyUserAttributeDto;
import com.springboot.cognito.exception.AwsSnsClientException;
import com.springboot.cognito.utils.AuthenticationHelper;
import com.springboot.cognito.utils.CommonMessages;

@Service
public class UserServiceImpl implements UserService{
	
	@Autowired
	private AWSCognitoIdentityProvider cognitoClient;

	@Value(value = "${aws.default-region}")
	private String region;
	@Value(value = "${aws.cognito.userPoolId}")
	private String userPoolId;
	@Value(value = "${aws.cognito.clientId}")
	private String clientId;

	private static String AUTHORIZATION = "Authorization";
	
	private static final String PHONE_NUMBER = "phone_number";
	
	@Override
	public OutputResponseDTO userSignUp(SignUpDto signUpDto) {
		OutputResponseDTO finalData = null;
		try {
			// creating user details payload for creating user into cognito user pool
			AdminCreateUserRequest cognitoRequest = new AdminCreateUserRequest().withUserPoolId(userPoolId)
					.withUsername(signUpDto.getEmail())
					.withUserAttributes(
									new AttributeType().withName("email").withValue(signUpDto.getEmail()),
									new AttributeType().withName("given_name").withValue(signUpDto.getFirstName()),
									new AttributeType().withName("family_name").withValue(signUpDto.getLastName()),
									new AttributeType().withName("email_verified").withValue("true"))
					.withTemporaryPassword(signUpDto.getPassword()).withMessageAction("SUPPRESS")
					.withDesiredDeliveryMediums(DeliveryMediumType.EMAIL).withForceAliasCreation(Boolean.FALSE);

			// initiate user create request to cognito user pool with user details payload
			AdminCreateUserResult createUserResult = cognitoClient.adminCreateUser(cognitoRequest);

			// checking result and setting response according to it
			if (createUserResult.getSdkHttpMetadata().getHttpStatusCode() == HttpStatus.OK.value()) {
				// Creating Payload to Disable force change password during first login
				AdminSetUserPasswordRequest adminSetUserPasswordRequest = new AdminSetUserPasswordRequest()
						.withUsername(signUpDto.getEmail()).withUserPoolId(userPoolId)
						.withPassword(signUpDto.getPassword()).withPermanent(true);

				// initiate request for Disable force change password during first login
				cognitoClient.adminSetUserPassword(adminSetUserPasswordRequest);
				finalData = new OutputResponseDTO(true, null, CommonMessages.USER_REGISTER_SUCCESS, CommonMessages.OK);
			} else {
				finalData = new OutputResponseDTO(false, null, CommonMessages.EXCEEPTION_MESSAGE,
						CommonMessages.INTERNAL_SERVER_ERROR);
			}
		} catch (Exception e) {
			finalData = new OutputResponseDTO(false, null, CommonMessages.EXCEEPTION_MESSAGE,
					CommonMessages.INTERNAL_SERVER_ERROR);
		}
		return finalData;
	}

	
	@Override
	public OutputResponseDTO userSignIn(LoginRequestDTO loginRequestDTO) {
		// Creating User signIn request payload
		UserSignInResponse userSignInResponse = new UserSignInResponse();
		final Map<String, String> authParams = new HashMap<>();
		authParams.put("USERNAME", loginRequestDTO.getEmail());
		authParams.put("PASSWORD", loginRequestDTO.getPassword());

		// set user sign in request with required params
		final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
		authRequest.withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
				   .withClientId(clientId)
				   .withUserPoolId(userPoolId)
				   .withAuthParameters(authParams);
		try {
			// initiate user sign-in request with AWS cognito
			AdminInitiateAuthResult result = cognitoClient.adminInitiateAuth(authRequest);
			AuthenticationResultType authenticationResult = null;

			// checking challenges returned by AWS cognito after sign-in request
			if (result.getChallengeName() != null && !result.getChallengeName().isEmpty()) {
				if (result.getChallengeName().contentEquals("SMS_MFA")) {
					// Getting session id from AWS cognito user sign-in request for MFA code
					// verification
					String sessionId = result.getSession();
					return new OutputResponseDTO(true, sessionId, CommonMessages.SMS_MFS_SEND, CommonMessages.OK);
				} else {
					return new OutputResponseDTO(true, null, "User has other challenge " + result.getChallengeName(),
							CommonMessages.OK);
				}
			} else {
				// if user don't have any challenges it will generate token for user
				authenticationResult = result.getAuthenticationResult();
				userSignInResponse.setAccessToken(authenticationResult.getAccessToken());
				userSignInResponse.setIdToken(authenticationResult.getIdToken());
				userSignInResponse.setRefreshToken(authenticationResult.getRefreshToken());
				userSignInResponse.setExpiresIn(authenticationResult.getExpiresIn());
				userSignInResponse.setTokenType(authenticationResult.getTokenType());
				return new OutputResponseDTO(true, userSignInResponse, CommonMessages.SIGN_IN_SUCCESS,CommonMessages.OK);
			}
		} catch (NotAuthorizedException e) {
			return new OutputResponseDTO(true, null, CommonMessages.INVALID_USER, CommonMessages.OK);
		} catch (Exception e) {
			return new OutputResponseDTO(true, null, CommonMessages.EXCEEPTION_MESSAGE,
					CommonMessages.INTERNAL_SERVER_ERROR);
		}
	}	
	
	
	@Override
	public OutputResponseDTO enableMFA(HttpServletRequest request,EnableMFADto enableMFADto) {
		OutputResponseDTO finalData=null;
		try {
			// Getting Access token from header for perform cognito operations
			String accessToken = request.getHeader(AUTHORIZATION).replaceFirst("Bearer ", "");

			// setting attribute info before enable MFA
			AttributeType attributeType = new AttributeType().withName(PHONE_NUMBER)
					.withValue(enableMFADto.getMobileNo());
			// building request payload for update mobile number with cognito user pool
			// before enable MFA
			UpdateUserAttributesRequest updateAttributeReqData = new UpdateUserAttributesRequest()
					.withAccessToken(accessToken).withUserAttributes(attributeType);
			// updating the user attribute with requested payload
			UpdateUserAttributesResult result = cognitoClient.updateUserAttributes(updateAttributeReqData);
			// Checking the status of request and return response according to it
			if (result.getSdkHttpMetadata().getHttpStatusCode() == HttpStatus.OK.value()) {
				// Requesting Verification code for associate mobile number
				GetUserAttributeVerificationCodeRequest getCodeRequest = new GetUserAttributeVerificationCodeRequest()
																		      .withAttributeName(PHONE_NUMBER)
																		      .withAccessToken(accessToken);
				// process the get verify attribute code request
				GetUserAttributeVerificationCodeResult resultData = cognitoClient
						.getUserAttributeVerificationCode(getCodeRequest);
				// Checking the status of request and return response according to it
				if (resultData.getSdkHttpMetadata().getHttpStatusCode() == HttpStatus.OK.value()) {
					finalData = new OutputResponseDTO(true, resultData, CommonMessages.VERIFICATION_CODE_SEND_MOBILE,
							CommonMessages.OK);
				} else {
					finalData = new OutputResponseDTO(true, "", CommonMessages.EXCEEPTION_MESSAGE,
							String.valueOf(resultData.getSdkHttpMetadata().getHttpStatusCode()));
				}
			} else {
				finalData = new OutputResponseDTO(true, "", CommonMessages.EXCEEPTION_MESSAGE,CommonMessages.INTERNAL_SERVER_ERROR);
			}
		}catch (Exception e) {
			finalData = new OutputResponseDTO(false, null, CommonMessages.EXCEEPTION_MESSAGE,CommonMessages.INTERNAL_SERVER_ERROR);
		}
		return finalData;
	}
	
	
	@Override
	public OutputResponseDTO getAttributeVerificationCode(HttpServletRequest request, EnableMFADto enableMFADto) {
		OutputResponseDTO finalData = null;
		try {
			// Getting Access token from header for perform cognito operations
			String accessToken = request.getHeader(AUTHORIZATION).replaceFirst("Bearer ", "");
			
			if(enableMFADto.getAttributeName().equals(PHONE_NUMBER)) {
				// setting attribute info before enable MFA
				AttributeType attributeType = new AttributeType().withName(PHONE_NUMBER)
						.withValue(enableMFADto.getMobileNo());
				// building request payload for update mobile number with cognito user pool
				// before enable MFA
				UpdateUserAttributesRequest updateAttributeReqData = new UpdateUserAttributesRequest() 
																		 .withAccessToken(accessToken)
																		 .withUserAttributes(attributeType);
				// updating the user attribute with requested payload
				UpdateUserAttributesResult result = cognitoClient.updateUserAttributes(updateAttributeReqData);
				
				if (result.getSdkHttpMetadata().getHttpStatusCode() == HttpStatus.OK.value()) {
					// Requesting Verification code for associate mobile number
					GetUserAttributeVerificationCodeRequest getCodeRequest = new GetUserAttributeVerificationCodeRequest()
							.withAttributeName(PHONE_NUMBER).withAccessToken(accessToken);
					// process the get verify attribute code request
					GetUserAttributeVerificationCodeResult resultData = cognitoClient
							.getUserAttributeVerificationCode(getCodeRequest);
					// Checking the status of request and return response according to it
					if (resultData.getSdkHttpMetadata().getHttpStatusCode() == HttpStatus.OK.value()) {
						finalData = new OutputResponseDTO(true, resultData, CommonMessages.VERIFICATION_CODE_SEND_MOBILE,
								CommonMessages.OK);
					} else {
						finalData = new OutputResponseDTO(true, "", CommonMessages.EXCEEPTION_MESSAGE,String.valueOf(resultData.getSdkHttpMetadata().getHttpStatusCode()));
					}
				} else {
					finalData = new OutputResponseDTO(true, "", CommonMessages.EXCEEPTION_MESSAGE,CommonMessages.INTERNAL_SERVER_ERROR);
				}
			}else {
				finalData = new OutputResponseDTO(false, "", CommonMessages.INVALID_ATTRIBUTE,CommonMessages.OK);
			}
		} catch (Exception e) {
			finalData = new OutputResponseDTO(false, null, CommonMessages.EXCEEPTION_MESSAGE,CommonMessages.INTERNAL_SERVER_ERROR);
		}
		return finalData;
	}
	
	@Override
	public OutputResponseDTO verifyUserAttribute(HttpServletRequest request,VerifyUserAttributeDto verifyUserAttributeDto) {
		OutputResponseDTO finalData = null;
		try {
			// Getting Access token from header for perform cognito operations
			String accessToken = request.getHeader(AUTHORIZATION).replaceFirst("Bearer ", "");
			// Building User Attribute Verification Payload
			VerifyUserAttributeRequest requestData = new VerifyUserAttributeRequest().withAccessToken(accessToken)
					.withAttributeName(verifyUserAttributeDto.getAttributeName())
					.withCode(verifyUserAttributeDto.getUserCode());

			// Initiate User Attribute Verification
			VerifyUserAttributeResult result = cognitoClient.verifyUserAttribute(requestData);

			// Checking with response of User Attribute Verification process
			if (result.getSdkHttpMetadata().getHttpStatusCode() == HttpStatus.OK.value()) {
				if (verifyUserAttributeDto.isEnable()) {
					finalData = new OutputResponseDTO(true, "", CommonMessages.MFA_ENABLED,CommonMessages.OK);
				} else {
					finalData = new OutputResponseDTO(true, "", CommonMessages.MFA_DISABLED,CommonMessages.OK);
				}
			} else {
				finalData = new OutputResponseDTO(false, "", CommonMessages.EXCEEPTION_MESSAGE,
						String.valueOf(result.getSdkHttpMetadata().getHttpStatusCode()));
			}
		} catch (CodeMismatchException e) {
			finalData = new OutputResponseDTO(false, null, CommonMessages.INVALID_CODE,
					CommonMessages.INTERNAL_SERVER_ERROR);
		} catch (ExpiredCodeException e) {
			finalData = new OutputResponseDTO(false, null, CommonMessages.INVALID_CODE,
					CommonMessages.MFA_CODE_EXPIRED);
		} catch (AwsSnsClientException e) {
			finalData = new OutputResponseDTO(false, null, CommonMessages.EXCEEPTION_MESSAGE,
					CommonMessages.INTERNAL_SERVER_ERROR);
		}
		return finalData;
	}
	
	@Override
	public OutputResponseDTO initiateUserSignInByEmailMFA(LoginRequestDTO loginRequestDTO) {
		OutputResponseDTO finalOutputData = null;
		AWSCognitoIdentityProvider awsCognitoIdentityProvider = AWSCognitoIdentityProviderClient.builder()
				.withRegion(Regions.DEFAULT_REGION).build();

		try {
			AuthenticationHelper helper = new AuthenticationHelper(userPoolId);

			// setting attribute info before enable MFA
			AttributeType attributeType = new AttributeType().withName("nickname")
					.withValue(loginRequestDTO.getOtpType());
			AdminUpdateUserAttributesRequest adminData = new AdminUpdateUserAttributesRequest()
					.withUsername(loginRequestDTO.getEmail()).withUserPoolId(userPoolId)
					.withUserAttributes(attributeType);
			AdminUpdateUserAttributesResult finalData = cognitoClient.adminUpdateUserAttributes(adminData);

			InitiateAuthResult initiateAuthResult = cognitoClient
					.initiateAuth(new InitiateAuthRequest().withClientId(clientId)
							.withAuthFlow(AuthFlowType.CUSTOM_AUTH).addAuthParametersEntry("CHALLENGE_NAME", "SRP_A")
							.addAuthParametersEntry("USERNAME", loginRequestDTO.getEmail())
							.addAuthParametersEntry("SRP_A", helper.getA().toString(16)));

			String userIdForSRP = initiateAuthResult.getChallengeParameters().get("USER_ID_FOR_SRP");
			String usernameInternal = initiateAuthResult.getChallengeParameters().get("USERNAME");
			String secretBlock = initiateAuthResult.getChallengeParameters().get("SECRET_BLOCK");
			BigInteger B = new BigInteger(initiateAuthResult.getChallengeParameters().get("SRP_B"), 16);
			BigInteger salt = new BigInteger(initiateAuthResult.getChallengeParameters().get("SALT"), 16);
			byte[] key = helper.getPasswordAuthenticationKey(userIdForSRP, loginRequestDTO.getPassword(), B, salt);

			Date timestamp = new Date();
			byte[] hmac = null;

			Mac mac = Mac.getInstance("HmacSHA256");
			SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
			mac.init(keySpec);
			mac.update(userPoolId.split("_", 2)[1].getBytes(StandardCharsets.UTF_8));
			mac.update(userIdForSRP.getBytes(StandardCharsets.UTF_8));
			mac.update(Base64.decodeBase64(secretBlock));

			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
			simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
			String dateString = simpleDateFormat.format(timestamp);
			byte[] dateBytes = dateString.getBytes(StandardCharsets.UTF_8);
			hmac = mac.doFinal(dateBytes);
			String signature = Base64.encodeBase64String(hmac);

			SimpleDateFormat formatTimestamp = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
			formatTimestamp.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

			Map<String, String> srpAuthResponses = new HashMap<String, String>();
			srpAuthResponses.put("PASSWORD_CLAIM_SECRET_BLOCK", secretBlock);
			srpAuthResponses.put("PASSWORD_CLAIM_SIGNATURE", signature);
			srpAuthResponses.put("TIMESTAMP", formatTimestamp.format(timestamp));
			srpAuthResponses.put("USERNAME", usernameInternal);

			RespondToAuthChallengeResult respondToAuthChallengeResult = awsCognitoIdentityProvider
					.respondToAuthChallenge(new RespondToAuthChallengeRequest().withClientId(clientId)
							.withChallengeResponses(srpAuthResponses).withChallengeName("PASSWORD_VERIFIER")
							.withSession(initiateAuthResult.getSession()));

			finalOutputData = new OutputResponseDTO(true, respondToAuthChallengeResult.getSession(),
					CommonMessages.VERIFICATION_CODE_SEND_ON+loginRequestDTO.getOtpType().toLowerCase(), CommonMessages.OK);
		}catch (NotAuthorizedException e) {
			finalOutputData = new OutputResponseDTO(false, "", CommonMessages.INVALID_USER,
					CommonMessages.OK);
		} catch (Exception e) {
			finalOutputData = new OutputResponseDTO(false, "", CommonMessages.EXCEEPTION_MESSAGE,
					CommonMessages.INTERNAL_SERVER_ERROR);
		}
		return finalOutputData;
	}
	
	@Override
	public OutputResponseDTO initiateEmailOtpVerification(OtpVerificaitonRequestDto otpVerificaitonRequestDto) {
		OutputResponseDTO finalOutputData = null;
		try {
			Map<String, String> srpAuthResponses = new HashMap<String, String>();
			srpAuthResponses.put("USERNAME", otpVerificaitonRequestDto.getUsername());
			srpAuthResponses.put("ANSWER", otpVerificaitonRequestDto.getMfaCode());

			RespondToAuthChallengeRequest request = new RespondToAuthChallengeRequest()
														.withClientId(clientId)
														.withChallengeName("CUSTOM_CHALLENGE")
														.withChallengeResponses(srpAuthResponses)
														.withSession(otpVerificaitonRequestDto.getSessionId());

			RespondToAuthChallengeResult result = cognitoClient.respondToAuthChallenge(request);
			if (result.getChallengeName() == null) {
				// Access the authenticated user's tokens and other information
				UserSignInResponse userSignInResponse = new UserSignInResponse();
				userSignInResponse.setAccessToken(result.getAuthenticationResult().getAccessToken());
				userSignInResponse.setIdToken(result.getAuthenticationResult().getIdToken());
				userSignInResponse.setRefreshToken(result.getAuthenticationResult().getRefreshToken());
				userSignInResponse.setExpiresIn(result.getAuthenticationResult().getExpiresIn());
				userSignInResponse.setTokenType(result.getAuthenticationResult().getTokenType());
				finalOutputData = new OutputResponseDTO(true, userSignInResponse, CommonMessages.SIGN_IN_SUCCESS,CommonMessages.OK);
			} else if (result.getChallengeName().equals("CUSTOM_CHALLENGE")
					&& result.getChallengeParameters().containsKey("USER_MFA_CODE")) {
				finalOutputData = new OutputResponseDTO(false, "", CommonMessages.REQUIRED_ADDITIONAL_VERIFICATION,CommonMessages.OK);
			} else {
				finalOutputData = new OutputResponseDTO(false, "", CommonMessages.INVALID_CODE,CommonMessages.INTERNAL_SERVER_ERROR);
			}
		} catch (NotAuthorizedException e) {
			finalOutputData = new OutputResponseDTO(false, "", CommonMessages.SESSION_EXPIRED,CommonMessages.INTERNAL_SERVER_ERROR);
		}catch (Exception e) {
			finalOutputData = new OutputResponseDTO(false, "", CommonMessages.EXCEEPTION_MESSAGE,CommonMessages.INTERNAL_SERVER_ERROR);
		}
		return finalOutputData;
	}
	
	
}
