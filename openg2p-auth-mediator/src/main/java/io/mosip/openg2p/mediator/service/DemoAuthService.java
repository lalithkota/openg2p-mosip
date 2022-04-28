package io.mosip.openg2p.mediator.service;

import io.mosip.openg2p.mediator.dto.CryptoResponse;
import io.mosip.openg2p.mediator.exception.BaseCheckedException;
import io.mosip.openg2p.mediator.util.CryptoUtil;
import io.mosip.openg2p.mediator.util.TokenUtil;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

@Service
public class DemoAuthService {

    private final Logger LOGGER = LoggerFactory.getLogger(DemoAuthService.class);

    @Value("${openg2p.mosip.kyc.type}")
    private String KYC_TYPE;
    @Value("${openg2p.mosip.kyc.status.un.success.with.errors}")
    private String UN_SUCCESS_WITH_ERRORS;
    @Value("${openg2p.mosip.kyc.status.success.with.errors}")
    private String SUCCESS_WITH_ERRORS;
    @Value("${openg2p.mosip.kyc.status.success}")
    private String SUCCESS;

    @Autowired
    private TokenUtil tokenUtil;

    @Autowired
    private CryptoUtil cryptoUtil;

    @Value("${mosip.ida.auth.url}")
    private String idaAuthUrl;
    @Value("${mosip.ida.auth.domain.uri}")
    private String idaAuthDomainUri;
    @Value("${mosip.ida.auth.version}")
    private String idaAuthVersion;
    @Value("${mosip.ida.auth.env}")
    private String idaAuthEnv;
    @Value("${mosip.ida.auth.request.id}")
    private String idaAuthReqId;
    @Value("${mosip.openg2p.partner.username}")
    private String partnerUsername;
    @Value("${mosip.openg2p.partner.apikey}")
    private String partnerApikey;
    @Value("${mosip.openg2p.partner.misp.lk}")
    private String partnerMispLK;
    @Value("${mosip.openg2p.demoAuth.full.address.order}")
    private String fullAddressOrder;
    @Value("${mosip.openg2p.demoAuth.full.address.separator}")
    private String fullAddressSeparator;
    @Value("${mosip.openg2p.demoAuth.dob.pattern}")
    private String mosipDobPattern;
    @Value("${openg2p.dob.pattern}")
    private String openg2pDobPattern;

    private SecureRandom secureRandom = null;

    public String authenticate(String upstreamRequest) {
        String txnId = randomAlphaNumericString(10);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        JSONObject upstreamJson;
        String vid,language,dob,fullName,phone,email,gender,fullAddress;
        try{
            upstreamJson = new JSONObject(upstreamRequest);
            language = convertLangCode(upstreamJson.getString("lang"));
            dob = convertDOB(upstreamJson.getString("dateofbirth"), openg2pDobPattern, mosipDobPattern);
            fullName = upstreamJson.getString("fullname");
            phone = upstreamJson.getString("phone");
            email = upstreamJson.getString("email");
            gender = upstreamJson.getString("gender");
            fullAddress = getFullAddressFromJson(upstreamJson, fullAddressOrder, fullAddressSeparator);
            vid = upstreamJson.getString("id");
        } catch (JSONException je) {
            String error = "Unable to parse request JSON. " + je.getMessage();
            LOGGER.error(error, je);
            return returnErrorResponse(sdf.format(new Date()),txnId,error);
        } catch (BaseCheckedException e) {
            LOGGER.error(e.getMessage(), e);
            return returnErrorResponse(sdf.format(new Date()),txnId,e.getMessage());
        }

        CryptoResponse encryptedRequest;
        String request = "{" +
            "\"timestamp\": \"" + sdf.format(new Date()) + "\"" + "," +
            "\"demographics\": {" +
                //"\"age\": \"" + Period.between(LocalDate.parse(dob, DateTimeFormatter.ofPattern(mosipDobPattern)), LocalDate.now()).getYears() + "\"" + "," +
                //"\"dob\": \"" + dob + "\"" + "," +
                "\"phoneNumber\": \"" + phone + "\"" + "," +
                "\"emailId\": \"" + email + "\"" + "," +
                "\"name\": [" +
                    "{" +
                        "\"language\": \"" + language + "\"" + "," +
                        "\"value\": \"" + fullName + "\"" +
                    "}" +
                "]" + "," +
                "\"gender\": [" +
                    "{" +
                        "\"language\": \"" + language + "\"" + "," +
                        "\"value\": \"" + gender + "\"" +
                    "}" +
                "]" + "," +
                "\"fullAddress\": [" +
                    "{" +
                        "\"language\": \"" + language + "\"" + "," +
                        "\"value\": \"" + fullAddress + "\"" +
                    "}" +
                "]" + "," +
                "\"metadata\": {}" +
            "}" + "," +
            "\"biometrics\": []" +
        "}";
        try{
            encryptedRequest = cryptoUtil.encryptSign(request);
        } catch(BaseCheckedException e) {
            String error = "Demo Auth Crypto - Error while Encrypting / Signing Request";
            LOGGER.error(error, e);
            return returnErrorResponse(sdf.format(new Date()), txnId,error);
        }
        LOGGER.info("Demo Auth Request - Successfully Encrypted Request");

        String downStreamRequest = "{" +
            "\"id\": \"" + idaAuthReqId + "\"" + "," +
            "\"version\": \"" + idaAuthVersion + "\"" + "," +
            "\"individualId\": \"" + vid + "\"" + "," +
            //"\"individualIdType\": \"VID\"" + "," +
            "\"transactionID\": \"" + txnId + "\"" + "," +
            "\"requestTime\": \"" + sdf.format(new Date()) + "\"" + "," +
            "\"specVersion\": \"" + idaAuthVersion + "\"" + "," +
            "\"thumbprint\": \"" + encryptedRequest.getThumbprint() + "\"" + "," +
            "\"domainUri\": \"" + idaAuthDomainUri + "\"" + "," +
            "\"env\": \"" + idaAuthEnv + "\"" + "," +
            "\"requestedAuth\": {" +
                "\"demo\": true" + "," +
                "\"pin\": false" + "," +
                "\"otp\": false" + "," +
                "\"bio\": false" +
            "}" + "," +
            "\"consentObtained\": true" + "," +
            "\"requestHMAC\": \"" + encryptedRequest.getHmacDigest() + "\"" + "," +
            "\"requestSessionKey\": \"" + encryptedRequest.getEncryptedKey() + "\"" + "," +
            "\"request\": \"" + encryptedRequest.getEncryptedBody() + "\"" + "," +
            "\"metadata\": {}" +
        "}";

        String jwtSign;
        try{
            jwtSign = cryptoUtil.jwtSign(downStreamRequest);
        } catch (BaseCheckedException e) {
            String error = "Demo Authentication JwtSign - Error getting signature";
            LOGGER.error(error,e);
            return returnErrorResponse(sdf.format(new Date()), txnId, error);
        }

        String token;
        try {
            token = tokenUtil.getPartnerAuthToken();
        } catch (BaseCheckedException e) {
            String error = "Demo Authentication Token - Error getting partner auth token";
            LOGGER.error(error,e);
            return returnErrorResponse(sdf.format(new Date()), txnId, error);
        }

        String response;
        try{
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.add("Authorization","Authorization=" + token);
            headers.add("Signature",jwtSign);
            HttpEntity<String> reqEnt = new HttpEntity<>(downStreamRequest,headers);
            RestTemplate restTemplate = new RestTemplate();
            response = restTemplate.postForObject(idaAuthUrl+"/"+partnerMispLK+"/"+partnerUsername+"/"+partnerApikey,reqEnt,String.class);
        } catch (Exception e) {
            String error = "Demo Authentication - Error while Authentication";
            LOGGER.error(error, e);
            return returnErrorResponse(sdf.format(new Date()), txnId, error + ": " + getStackTrace(e));
        }

        return handleResponse(response, sdf.format(new Date()), txnId);
    }

    private String handleResponse(String response, String timestamp, String txnId){
        try{
            JSONObject json = new JSONObject(response);
            if(json.has("errors") && !json.isNull("errors")){
                JSONArray errors = json.getJSONArray("errors");
                if(json.has("response") && !json.isNull("response") && json.getJSONObject("response").has("authToken") && !json.getJSONObject("response").isNull("authToken")){
                    String authToken = json.getJSONObject("response").getString("authToken");
                    return returnAuthResponse(timestamp, txnId, authToken, SUCCESS_WITH_ERRORS, collateErrors(errors));
                } else {
                    return returnErrorResponse(timestamp, txnId, collateErrors(errors));
                }
            } else {
                if(json.has("response") && !json.isNull("response")){
                    JSONObject resJson = json.getJSONObject("response");
                    if(resJson.has("authStatus") && !resJson.isNull("authStatus") && resJson.getBoolean("authStatus")){
                        if(resJson.has("authToken") && !resJson.isNull("authToken")){
                            return returnAuthResponse(timestamp, txnId, resJson.getString("authToken"), SUCCESS, "All Success");
                        } else {
                            return returnAuthResponse(timestamp, txnId, "", SUCCESS_WITH_ERRORS, "Kyc Id not found, but returned Success.");
                        }
                    } else {
                        if(resJson.has("authToken") && !resJson.isNull("authToken")){
                            return returnAuthResponse(timestamp,txnId, resJson.getString("authToken"), SUCCESS_WITH_ERRORS, "Unknown Kyc Status, but no errors.");
                        } else {
                            return returnErrorResponse(timestamp,txnId, "Unknown error: Improper response from mosip.");
                        }
                    }
                } else {
                    return returnErrorResponse(timestamp,txnId,"UNKNOWN");
                }
            }
        } catch(JSONException je) {
            String error="Unable to parse response json.";
            LOGGER.error(error, je);
            return returnErrorResponse(timestamp,txnId, error + getStackTrace(je));
        }
    }

    public static String getStackTrace(Throwable e){
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }

    public String randomAlphaNumericString(int size){
        if(secureRandom == null)
            secureRandom = new SecureRandom();
        return secureRandom.ints(48, 123)
            .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
            .limit(size)
            .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
            .toString();
    }

    private String returnAuthResponse(String timestamp, String txnId, String authToken, String authStatus, String authMessage){
        return "{" +
            "\"timestamp\": \"" + timestamp + "\"" + "," +
            "\"txnId\": \"" + txnId + "\"" + "," +
            "\"authIdType\": \"" + KYC_TYPE + "\"" + "," +
            "\"authId\": \"" + authToken + "\"" + "," +
            "\"authIdStatus\": \"" + authStatus + "\"" + "," +
            "\"authIdMessage\":\"" + authMessage + "\"" +
        "}";
    }

    private String returnErrorResponse(String timestamp, String txnId, String error){
        return returnAuthResponse(timestamp,txnId,"",UN_SUCCESS_WITH_ERRORS,error);
    }

    private String collateErrors(JSONArray jArr) throws JSONException{
        String err = "";
        for(int i=0;i<jArr.length();i++){
            if(i!=0)err+="&&";
            err+=jArr.getJSONObject(i).getString("errorMessage");
            if(jArr.getJSONObject(i).has("actionMessage")){
                err+=":";
                err+=jArr.getJSONObject(i).getString("actionMessage");
            }
        }
        return err;
    }

    private String getFullAddressFromJson(JSONObject json, String order, String separator) throws JSONException{
        String fAddress = "";
        String[] orderArr = order.replaceAll("\\s","").split(",");
        for(int i=0; i<orderArr.length; i++){
            if(i>0)fAddress+=separator.replaceAll("'","");
            fAddress+=json.getString(orderArr[i]);
        }
        return fAddress;
    }

    private String convertLangCode(String langCode){
        String[] localeArray = langCode.split("-");
        try {
            if (localeArray.length > 1) {
                return new Locale(localeArray[0], localeArray[1]).getISO3Language();
            } else {
                localeArray = langCode.split("_");
                if (localeArray.length > 1) {
                    return new Locale(localeArray[0], localeArray[1]).getISO3Language();
                } else {
                    return new Locale(langCode).getISO3Language();
                }
            }
        } catch (Exception e) {
            LOGGER.error("Unable to convert language code.", e);
            return langCode;
        }
    }

    private String convertDOB(String dob, String originalPattern, String targetPattern) throws BaseCheckedException{
        SimpleDateFormat originalFormat = new SimpleDateFormat(originalPattern);
        SimpleDateFormat targetFormat = new SimpleDateFormat(targetPattern);
        try{
            Date date = originalFormat.parse(dob);
            return targetFormat.format(date);
        } catch (Exception e) {
            throw new BaseCheckedException("","Unable to convert DOB",e);
        }
    }
}
