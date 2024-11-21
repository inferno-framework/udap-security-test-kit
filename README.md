# Inferno UDAP Security IG Test Kit 

This is a collection of tests to verify server conformance to the [HL7 UDAP Security
STU 1.0 IG](https://hl7.org/fhir/us/udap-security/STU1/index.html). 
Specifically, this test
kit assesses the required capabilities from the following sections:
- [JSON Web Token (JWT) Requirements](https://hl7.org/fhir/us/udap-security/STU1/index.html)
- [Discovery](https://hl7.org/fhir/us/udap-security/STU1/discovery.html)
- [Dynamic Client Registration](https://hl7.org/fhir/us/udap-security/STU1/registration.html)
- [Consumer-Facing Authorization & Authentication](https://hl7.org/fhir/us/udap-security/STU1/registration.html)
- [Business-to-Business (B2B) Authorization & Authentication](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)

[Tiered OAuth for User
Authentication](https://hl7.org/fhir/us/udap-security/STU1/user.html) is not a
required capability and is not assessed. 
This test kit also does not assess client conformance.

## Instructions

- Clone this repo.
- Run `setup.sh` in this repo
- Run `run.sh` in this repo.
- Navigate to `http://localhost`. The UDAP test suite will be available.
- Prior to running Dynamic Client Registration tests or Authorization tests, the
  authorization server under test MUST be configured to trust the signing
  certificate that issues and signs the client certificates. See the following
  section for more details. 

### Certificate Setup for Running Tests

Running UDAP Dynamic Client Registration and Authorization tests requires the
use of X.509 certificates that are trusted by the authorization server under
test.  There are two categories of certificates for this test kit:
- Client certificates: represent the logical instance of a UDAP client interfacing
  with the authorization server.  This test
  kit supports multiple logical clients, and a new logical client is needed for each instance of
  testing Dynamic Client Registration. 
- Signing certificate: the certificate used to issue and sign the client
  certificates.

Testers must provide their own client certificate(s) via the
test inputs.  Currently, the certificates available in `lib/udap_security_test_kit/certs`
are for unit testing only.

In order for tests to pass, register your own signing certificate as a trust anchor with
the authorization server under tests. 


## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at
```
http://www.apache.org/licenses/LICENSE-2.0
```
Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
