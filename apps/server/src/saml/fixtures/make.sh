#!/bin/sh
# Builds a SAML Response signed with tools other than the server's own code: libxml2 for exclusive
# canonicalisation, openssl for the digest and the RSA signature. The key is made in a temporary
# directory and thrown away: only the certificate and the signed response are kept, next to this
# script. `sh make.sh` rebuilds both (the tests' expected subject and times are fixed).
set -eu
OUT=$(cd "$(dirname "$0")" && pwd)
cd "$(mktemp -d)"
openssl genrsa -out key.pem 2048 2>/dev/null
openssl req -x509 -new -key key.pem -subj /CN=fixture-idp -days 36500 -out cert.pem 2>/dev/null
SAML=urn:oasis:names:tc:SAML:2.0:assertion
SP=https://pass.example.com/v1/sso/saml/0192f000-0000-7000-8000-000000000001
ATTRS='ID="_fixture-assertion" Version="2.0" IssueInstant="2026-11-08T10:00:00Z"'
BODY='<saml:Issuer>https://idp.example.com/saml</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">fixture-subject-42</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_fixture-request" NotOnOrAfter="2026-11-08T10:05:00Z" Recipient="'$SP'/acs"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2026-11-08T09:59:00Z" NotOnOrAfter="2026-11-08T10:05:00Z"><saml:AudienceRestriction><saml:Audience>'$SP'/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2026-11-08T10:00:00Z" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Member@Example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
ISSUER='<saml:Issuer>https://idp.example.com/saml</saml:Issuer>'
REST=${BODY#"$ISSUER"}
printf '<saml:Assertion xmlns:saml="%s" %s>%s</saml:Assertion>' "$SAML" "$ATTRS" "$BODY" > assertion.xml
DIGEST=$(xmllint --exc-c14n assertion.xml | openssl dgst -sha256 -binary | openssl base64 -A)
SI_INNER='<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_fixture-assertion"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>'$DIGEST'</ds:DigestValue></ds:Reference>'
printf '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%s</ds:SignedInfo>' "$SI_INNER" > signedinfo.xml
SIGNATURE=$(xmllint --exc-c14n signedinfo.xml | openssl dgst -sha256 -sign key.pem | openssl base64 -A)
CERT=$(grep -v CERTIFICATE cert.pem | tr -d '\n')
SIG='<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'$SI_INNER'</ds:SignedInfo><ds:SignatureValue>'$SIGNATURE'</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'$CERT'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>'
printf '<?xml version="1.0" encoding="UTF-8"?>\n<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="%s" ID="_fixture-response" Version="2.0" IssueInstant="2026-11-08T10:00:00Z" Destination="%s/acs" InResponseTo="_fixture-request">\n  <saml:Issuer>https://idp.example.com/saml</saml:Issuer>\n  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>\n  <saml:Assertion xmlns:saml="%s" %s>%s%s%s</saml:Assertion>\n</samlp:Response>\n' "$SAML" "$SP" "$SAML" "$ATTRS" "$ISSUER" "$SIG" "$REST" > response.xml
xmllint --noout response.xml
cp response.xml "$OUT/signed-response.xml"
cp cert.pem "$OUT/idp-cert.pem"
