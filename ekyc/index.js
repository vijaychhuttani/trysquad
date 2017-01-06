var request = require('request');
var pem = require('pem');
var SignedXml = require('xml-crypto').SignedXml;
var moment = require('moment-timezone');
var xml2json = require('xml2json');
var crypto = require('crypto');
var fs = require("fs");
var constants = require("constants");

module.exports = function(app){
	
	var AADHAR_BASE_URL = "http://developer.uidai.gov.in";
	
	// Test data is obtained through https://developer.uidai.gov.in/node/21
	var AADHAR_AUA_CODE = "public"; // use public for testing purpose
	var AADHAR_SUB_AUA_CODE = "public"; // use public for testing purpose
	var AADHAR_AUA_LICENSE_KEY = "MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg" // use MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg for testing purpose
	var AADHAR_ASA_LICENSE_KEY = "MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo"; // use MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo for testing purpose
	var AADHAR_TERMINAL_ID = "public"; // use public for public devices
	
	var KEY_STORE_FILE_PATH = "./ekyc/aadhar/Staging_Signature_PrivateKey.p12";
	var KEY_STORE_PASSWORD = "public";
	
	var UIDAI_PUBLIC_KEY_CERTIFICATE_PATH="./ekyc/aadhar/uidai_auth_stage.cer";
	
	// To test the end point, try
	// curl -H "Content-Type: application/json" -X POST -d '{"aadharNumber":"999999990019"}' http://playground.trysquad.com/api/ekyc/aadhar/otp
	app.post('/api/ekyc/aadhar/otp', function (req, res) {

		var aadharNumber = req.body.aadharNumber;
		var AADHAR_OTP_API_VERSION = "1.6";
		
		readDataFromKeyStore(function(x509Certificate, x509CertificateInfo, privateKey){
			
			var txn = getTxn(AADHAR_AUA_CODE);
			var xml = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?><Otp uid='"+aadharNumber+"' tid='"+AADHAR_TERMINAL_ID+"' ac='"+AADHAR_AUA_CODE+"' sa='"+AADHAR_SUB_AUA_CODE+"' ver='"+AADHAR_OTP_API_VERSION+"' txn='"+txn+"' lk='"+AADHAR_AUA_LICENSE_KEY+"' type='A' ts='"+getCurrentTimestamp("YYYY-MM-DDThh:mm:ss")+"'><Opts ch='00'/></Otp>";
			var signedXML = signXML(xml, x509Certificate, x509CertificateInfo, privateKey);
			
			// Get the URL for Aadhar OTP
			var aadharOTPRequestUrl = AADHAR_BASE_URL+"/otp/"+AADHAR_OTP_API_VERSION+"/"+AADHAR_AUA_CODE+"/"+aadharNumber.charAt(0)+"/"+aadharNumber.charAt(1)+"/"+encodeURI(AADHAR_ASA_LICENSE_KEY);		
			var options = {
				url: aadharOTPRequestUrl,
				method: 'POST',
				headers: {
					'Content-Type': 'text/xml'
				},
				body: signedXML
			}

			request(options, function (error, response, body) {
				if(error){
					res.send(error);
				}else{
					res.send(xml2json.toJson(body));
				}
			});
		});
	});
	
	// To test the end point, try
	// curl -H "Content-Type: application/json" -X POST -d '{"aadharNumber":"999999990019", "otp":"12345"}' http://playground.trysquad.com/api/ekyc/aadhar/ekyc
	app.post('/api/ekyc/aadhar/ekyc', function (req, res){
		
		var aadharNumber = req.body.aadharNumber;
		var otp = req.body.otp;
		var AADHAR_EKYC_API_VERSION = "2.0";
		
		var timestamp = getCurrentTimestamp("YYYY-MM-DDThh:mm:ss");
		
		readDataFromKeyStore(function(x509Certificate, x509CertificateInfo, privateKey, publicKey){
			readUIDAIPublicCertificate(function(uidaiX509Certificate, uidaiX509CertificateInfo, uidaiPublicKey){
				
				// Generate Pid Block
				var pidXML = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?><ns2:Pid ts='"+timestamp+"' xmlns:ns2='http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0'><Pv otp='"+otp+"'/></ns2:Pid>";

				// Construct Aadhar auth xml
				var txn = "UKC:"+getCurrentTimestamp("YYYYMMDDThhmmss");
				var sessionKey = crypto.randomBytes(32); 
				
				var pidXMLBuffer = new Buffer(pidXML);
				
				// encrypt pid xml
				var aes256PidXmlCipher = crypto.createCipher('aes-256-cbc', sessionKey);
				var base64EncodedAES256EncryptedPidXml = aes256PidXmlCipher.update(pidXMLBuffer);
				base64EncodedAES256EncryptedPidXml = Buffer.concat([base64EncodedAES256EncryptedPidXml, aes256PidXmlCipher.final()]);
				base64EncodedAES256EncryptedPidXml = base64EncodedAES256EncryptedPidXml.toString('base64');
				
				// Next encrypt sha256 hash of pid block
				aes256PidXmlCipher = crypto.createCipher('aes-256-cbc', sessionKey);
				var sha256Hash = crypto.createHash('sha256');
				var pidXMLSha256Hash = sha256Hash.update(pidXML).digest();
				var base64EncodedPidXMLSha256Hash = aes256PidXmlCipher.update(pidXMLSha256Hash);
				base64EncodedPidXMLSha256Hash = Buffer.concat([base64EncodedPidXMLSha256Hash, aes256PidXmlCipher.final()]);
				base64EncodedPidXMLSha256Hash = base64EncodedPidXMLSha256Hash.toString('base64');
				
				// Generate certificate identifier which is its expiry date
				var uidaiCertificateExpirationDate = moment(uidaiX509CertificateInfo.validity.end).format("YYYYMMDD");
				
				// Encrypt session id 
				var base64EncodedEncryptedSessionKey = crypto.publicEncrypt({"key":uidaiPublicKey, padding:constants.RSA_PKCS1_PADDING}, sessionKey).toString('base64');
		
				var aadharAuthXML="<?xml version='1.0' encoding='UTF-8' standalone='yes'?><Auth uid='"+aadharNumber+"' ac='"+AADHAR_AUA_CODE+"' tid='"+AADHAR_TERMINAL_ID+"' ver='1.6' txn='"+txn+"' lk='"+AADHAR_AUA_LICENSE_KEY+"' sa='"+AADHAR_SUB_AUA_CODE+"' xmlns='http://www.uidai.gov.in/authentication/uid-auth-request/1.0'><Uses pi='n' pa='n' pfa='n' bio='n' bt='' pin='n' otp='y'/><Meta udc='"+getTerminalDeviceCode()+"' pip='127.0.0.1' fdc='NC' idc='NA' lot='P' lov='"+getLocationPinCode()+"'/><Skey ci='"+uidaiCertificateExpirationDate+"'>"+base64EncodedEncryptedSessionKey+"</Skey><Data type='X'>"+base64EncodedAES256EncryptedPidXml+"</Data><Hmac>"+base64EncodedPidXMLSha256Hash+"</Hmac></Auth>";
				var signedAadharAuthXml = signXML(aadharAuthXML, x509Certificate, x509CertificateInfo, privateKey);
				
				// Finally, construct ekyc xml
				var base64EncodedAadharAuthXML = new Buffer(signedAadharAuthXml).toString('base64');
				var eKYCXML = "<?xml version='1.0' encoding='UTF-8'?><Kyc xmlns='http://www.uidai.gov.in/kyc/uid-kyc-request/1.0' de='Y' lr='N' mec='N' pfr='Y' ra='O' rc='Y' ts='"+timestamp+"' ver='"+AADHAR_EKYC_API_VERSION+"'><Rad>"+base64EncodedAadharAuthXML+"</Rad></Kyc>";
				var signedEKYCXML = signXML(eKYCXML, x509Certificate, x509CertificateInfo, privateKey);
				
				var aadharEKYCRequestUrl = AADHAR_BASE_URL+"/kyc/"+AADHAR_EKYC_API_VERSION+"/"+AADHAR_AUA_CODE+"/"+aadharNumber.charAt(0)+"/"+aadharNumber.charAt(1)+"/"+encodeURI(AADHAR_ASA_LICENSE_KEY);
				
				var options = {
					url: aadharEKYCRequestUrl,
					method: 'POST',
					headers: {
						'Content-Type': 'text/xml'
					},
					body: signedEKYCXML
				}
			
				request(options, function (error, response, body) {
					if(error){
						res.send(error);
					}else{
						var resJson = xml2json.toJson(body);
						// TBD decode and decrypt KycRes
						res.send(resJson);
					}
				});
			});
		});
	});

	function guid(){
		function s4() 
		{
			return Math.floor((1 + Math.random()) * 0x10000)
			.toString(16)
			.substring(1);
		}
		return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
		s4() + '-' + s4() + s4() + s4();
	}
	function getCurrentTimestamp(formatStr){
		return moment().tz("Asia/Kolkata").format(formatStr);
	}
	function getTxn(aadharAUACode){
		return "TrySquadServer:"+aadharAUACode+":"+getCurrentTimestamp("YYYYMMDDThhmmss");
	}
	function signXML(xml, x509Certificate, x509CertificateInfo, privateKey){
	
		var sig = new SignedXml();
		sig.addReference(
			// reference to the root node
			"/*",
			[
				'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
				'http://www.w3.org/2001/10/xml-exc-c14n#'
			],
			'http://www.w3.org/2000/09/xmldsig#sha1',
			'',
			'',
			'',
			// let the URI attribute with an empty value,
			// this is the signal that the signature is affecting the whole xml document
			true
		);
		sig.signingKey = privateKey;
		sig.keyInfoProvider = new XmlSigningKeyInfoProvider(x509Certificate, x509CertificateInfo);
		sig.computeSignature(xml);
		return sig.getSignedXml();
	}
	function XmlSigningKeyInfoProvider(x509Certificate, x509CertificateInfo) {
		this.x509Certificate = x509Certificate;
		this.x509CertificateInfo = x509CertificateInfo;

		this.getKeyInfo = function(key, prefix) {
			
			var certBegin = "-----BEGIN CERTIFICATE-----";
			var certEnd = "-----END CERTIFICATE-----";
			
			prefix = prefix || '';
			prefix = prefix ? prefix + ':' : prefix;
			var subject="CN="+this.x509CertificateInfo.commonName+",O="+this.x509CertificateInfo.organization+",ST="+this.x509CertificateInfo.state+",C="+this.x509CertificateInfo.country;
			var keyInfo = "<"+prefix+"X509SubjectName>"+subject+"</"+prefix+"X509SubjectName><"+prefix+"X509Certificate>"+this.x509Certificate.replace(certBegin,'').replace(certEnd,'')+"</"+prefix+"X509Certificate>";
			return "<" + prefix + "X509Data>"+keyInfo+"</" + prefix + "X509Data>";
		}

		this.getKey = function(keyInfo) {
			return this.x509Certificate;
		}
	}
	function readDataFromKeyStore(cb){
		pem.readPkcs12(KEY_STORE_FILE_PATH, {p12Password:KEY_STORE_PASSWORD}, function(err, data){
			
			var x509Certificate = data.cert;
			var privateKey = data.key;
	
			// Ready certificate info from certificate
			pem.readCertificateInfo(x509Certificate, function(err, x509CertificateInfo){
				pem.getPublicKey(x509Certificate, function(err, pk){
					cb(x509Certificate, x509CertificateInfo, privateKey, pk.publicKey);
				});
			});	
		});
	}
	function readUIDAIPublicCertificate(cb){
		var x509Certificate = fs.readFileSync(UIDAI_PUBLIC_KEY_CERTIFICATE_PATH);
		pem.readCertificateInfo(x509Certificate, function(err, x509CertificateInfo){
			// Read public key from certificate
			pem.getPublicKey(x509Certificate, function(err, pk){
				cb(x509Certificate, x509CertificateInfo, pk.publicKey);
			});
		});	
	}
	function getTerminalDeviceCode(){
		return "UKC:TrySquadServer";
	}
	function getLocationPinCode(){
		return "311001";
	}
};

