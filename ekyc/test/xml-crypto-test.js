var select = require('xml-crypto').xpath
, SignedXml = require('xml-crypto').SignedXml
, FileKeyInfo = require('xml-crypto').FileKeyInfo
, dom = require('xmldom').DOMParser
, fs = require('fs')

// Read certificate info from key store
readDataFromKeyStore(function(x509Certificate, x509CertificateInfo, privateKey, publicKey){
	var xml = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?><Otp uid='999999990019' tid='public' ac='public' sa='public' ver='1.6' txn='TrySquadServer:public:20170103T023103' lk='MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg' type='A'><Opts ch='00'/></Otp>"
	var signedXml = signRoot(xml, x509Certificate, x509CertificateInfo, privateKey, publicKey);
	verifySignedRoot(signedXml, x509Certificate, x509CertificateInfo, privateKey, publicKey);
});

function signRoot(xml, x509Certificate, x509CertificateInfo, privateKey, publicKey){
	
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
function verifySignedRoot(signedXml, x509Certificate, x509CertificateInfo, privateKey, publicKey){
	var doc = new dom().parseFromString(signedXml);
	var signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
	var sig = new SignedXml();
	sig.keyInfoProvider = new XmlSigningKeyInfoProvider(x509Certificate, x509CertificateInfo, publicKey);
	sig.loadSignature(signature);
	var verifySignedXmlResponse = sig.checkSignature(signedXml);
	if (!verifySignedXmlResponse) console.log(sig.validationErrors);
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
	
	var keyStoreFilePath = "./Staging_Signature_PrivateKey.p12";
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