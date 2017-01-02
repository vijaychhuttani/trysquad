var express = require('express');
var app = express();
var request = require('request');
var bodyParser = require('body-parser');
var pem = require('pem');
var SignedXml = require('xml-crypto').SignedXml;

app.use(bodyParser.json());

// Test data is obtained through https://developer.uidai.gov.in/node/21
var aadharAUACode = "public"; // use public for testing purpose
var aadharSubAUACode = "public"; // use public for testing purpose
var aadharAUALicenseKey = "MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg" // use MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg for testing purpose
var aadharASALicenseKey = "MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo"; // use MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo for testing purpose
var aadharDeviceId = "public"; // use public for public devices

var aadharOTPAPIVersion = "1.6";

// To test the end point, try
// curl -H "Content-Type: application/json" -X POST -d '{"aadharNumber":"999999990019"}' http://playground.trysquad.com/api/ekyc/aadhar/otp
app.post('/api/ekyc/aadhar/otp', function (req, res) {

	var aadharNumber = req.body.aadharNumber;
	
	// Generate data that needs to be POSTED to send OTP via SMS and Email to the aadhar card owner
	getAadharOTPData(aadharNumber,
		aadharDeviceId,
		aadharAUACode,
		aadharSubAUACode,
		aadharOTPAPIVersion,
		aadharAUALicenseKey,
		function(data){
			
			// Get the URL for Aadhar OTP
			var aadharOTPRequestUrl = "http://developer.uidai.gov.in/otp/"+aadharOTPAPIVersion+"/"+aadharAUACode+"/"+aadharNumber.charAt(0)+"/"+aadharNumber.charAt(1)+"/"+encodeURI(aadharASALicenseKey);
			
			var options = {
				url: aadharOTPRequestUrl,
				method: 'POST',
				headers: {
					'Content-Type': 'text/xml'
				},
				body: data
			}

			request(options, function (error, response, body) {
				res.set('Content-Type', 'text/xml');
				
				// Temporarily send request params as well. Ideally in production, we only want to send status code back
				res.send("<Result><Request><Url>"+aadharOTPRequestUrl+"</Url><Body>"+data+"</Body</Request><Response><Body>"+body+"</Body><Error>"+error+"</Error></Response></Result>");
			});
		}
	);
});

function getAadharOTPData(aadharNumber,
	aadharDeviceId,
	aadharAUACode,
	aadharSubAUACode,
	aadharOTPAPIVersion,
	aadharAUALicenseKey,
	cb
){
	var txn = getTxn(aadharAUACode);
	var xml = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?><Otp uid='"+aadharNumber+"' tid='"+aadharDeviceId+"' ac='"+aadharAUACode+"' sa='"+aadharSubAUACode+"' ver='"+aadharOTPAPIVersion+"' txn='"+txn+"' lk='"+aadharAUALicenseKey+"' type='A'><Opts ch='00'/></Otp>";
	signXML(xml, cb);
}

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
function signXML(xml, cb){
	var keyStoreFilePath = "aadhar/Staging_Signature_PrivateKey.p12";
	var keyStoreAlias = "public";
	var keyStorePassword = "public";
	
	// Read keystore
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
				
				// Sign the XML and include key info in block 
				var sig = new SignedXml();
				sig.signingKey = privateKey;
				sig.keyInfoProvider = new XmlSigningKeyInfoProvider(x509Certificate, x509CertificateInfo, publicKey);
				sig.computeSignature(xml);
				cb(sig.getSignedXml());
			});
		});
	});
}
// Function to return keyInfo element used during Digital Signature 
function XmlSigningKeyInfoProvider(x509Certificate, x509CertificateInfo, publicKey) {
	this.x509Certificate = x509Certificate;
	this.x509CertificateInfo = x509CertificateInfo;
	this.publicKey = publicKey;

	this.getKeyInfo = function(key, prefix) {
		prefix = prefix || '';
		prefix = prefix ? prefix + ':' : prefix;
		var subject="CN="+this.x509CertificateInfo.commonName+",O="+this.x509CertificateInfo.organization+",ST="+this.x509CertificateInfo.state+",C="+this.x509CertificateInfo.country+"";
		var keyInfo = "<"+prefix+"X509SubjectName>"+subject+"</"+prefix+"X509SubjectName><"+prefix+"X509Certificate>"+this.publicKey+"</"+prefix+"X509Certificate>";
		return "<" + prefix + "X509Data>"+keyInfo+"</" + prefix + "X509Data>";
	}

	this.getKey = function(keyInfo) {
		return this.x509Certificate;
	}
}

app.listen(process.env.PORT || 3000, function () {
	console.log('App listening on port 3000!')
})