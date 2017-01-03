var request = require('request');
var pem = require('pem');
var SignedXml = require('xml-crypto').SignedXml;

module.exports = function(app){
	
	// Test data is obtained through https://developer.uidai.gov.in/node/21
	var aadharAUACode = "public"; // use public for testing purpose
	var aadharSubAUACode = "public"; // use public for testing purpose
	var aadharAUALicenseKey = "MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg" // use MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg for testing purpose
	var aadharASALicenseKey = "MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo"; // use MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo for testing purpose
	var aadharDeviceId = "public"; // use public for public devices

	// To test the end point, try
	// curl -H "Content-Type: application/json" -X POST -d '{"aadharNumber":"999999990019"}' http://playground.trysquad.com/api/ekyc/aadhar/otp
	app.post('/api/ekyc/aadhar/otp', function (req, res) {

		var aadharNumber = req.body.aadharNumber;
		var aadharOTPAPIVersion = "1.6";
		
		readDataFromKeyStore(function(x509Certificate, x509CertificateInfo, privateKey, publicKey){
			
			var txn = getTxn(aadharAUACode);
			var xml = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?><Otp uid='"+aadharNumber+"' tid='"+aadharDeviceId+"' ac='"+aadharAUACode+"' sa='"+aadharSubAUACode+"' ver='"+aadharOTPAPIVersion+"' txn='"+txn+"' lk='"+aadharAUALicenseKey+"' type='A'><Opts ch='00'/></Otp>";
			var signedXML = signXML(xml, x509Certificate, x509CertificateInfo, privateKey, publicKey);
			
			// Get the URL for Aadhar OTP
			var aadharOTPRequestUrl = "http://developer.uidai.gov.in/otp/"+aadharOTPAPIVersion+"/"+aadharAUACode+"/"+aadharNumber.charAt(0)+"/"+aadharNumber.charAt(1)+"/"+encodeURI(aadharASALicenseKey);
			var options = {
				url: aadharOTPRequestUrl,
				method: 'POST',
				headers: {
					'Content-Type': 'text/xml'
				},
				body: signedXML
			}

			request(options, function (error, response, body) {
				res.set('Content-Type', 'text/xml');

				// Temporarily send request params as well. Ideally in production, we only want to send status code back
				res.send("<Result><Request><Url>"+aadharOTPRequestUrl+"</Url><Body>"+signedXML+"</Body></Request><Response><Body>"+body+"</Body><Error>"+error+"</Error></Response></Result>");
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
	function getTxn(aadharAUACode){
		var moment = require('moment-timezone');
		return "TrySquadServer:"+aadharAUACode+":"+moment().tz("Asia/Kolkata").format("YYYYMMDDThhmmss");
	}
	function signXML(xml, x509Certificate, x509CertificateInfo, privateKey, publicKey){
	
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
		sig.keyInfoProvider = new XmlSigningKeyInfoProvider(x509Certificate, x509CertificateInfo, publicKey);
		sig.computeSignature(xml);
		return sig.getSignedXml();
	}
	function XmlSigningKeyInfoProvider(x509Certificate, x509CertificateInfo, publicKey) {
		this.x509Certificate = x509Certificate;
		this.x509CertificateInfo = x509CertificateInfo;
		this.publicKey = publicKey;

		this.getKeyInfo = function(key, prefix) {
			prefix = prefix || '';
			prefix = prefix ? prefix + ':' : prefix;
			var subject="CN="+this.x509CertificateInfo.commonName+",O="+this.x509CertificateInfo.organization+",ST="+this.x509CertificateInfo.state+",C="+this.x509CertificateInfo.country;
			var keyInfo = "<"+prefix+"X509SubjectName>"+subject+"</"+prefix+"X509SubjectName><"+prefix+"X509Certificate>"+this.publicKey+"</"+prefix+"X509Certificate>";
			return "<" + prefix + "X509Data>"+keyInfo+"</" + prefix + "X509Data>";
		}

		this.getKey = function(keyInfo) {
			return this.x509Certificate;
		}
	}
	function readDataFromKeyStore(cb){
	
		var keyStoreFilePath = "./ekyc/aadhar/Staging_Signature_PrivateKey.p12";
		var keyStorePassword = "public";
	
		var pem = require('pem');
		pem.readPkcs12(keyStoreFilePath, {p12Password:keyStorePassword}, function(err, data){
			var x509Certificate = data.cert;
			var privateKey = data.key;
	
			// Ready certificate info from certificate
			pem.readCertificateInfo(x509Certificate, function(err, x509CertificateInfo){
		
				// Read public key from certificate
				pem.getPublicKey(x509Certificate, function(err, pk){
				
					var publicKey = pk.publicKey;
					var certBegin = "-----BEGIN PUBLIC KEY-----\n";
					var certEnd = "\n-----END PUBLIC KEY-----";
					publicKey = publicKey.replace(certBegin,'').replace(certEnd,'');
				
					cb(x509Certificate, x509CertificateInfo, privateKey, publicKey);
				});
			});	
		});
	}
};

