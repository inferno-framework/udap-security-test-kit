# Inferno UDAP Security IG Test Kit 

This is a collection of tests for the [UDAP Security
IG](https://hl7.org/fhir/us/udap-security/index.html).

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
  kit supports multiple logical clients, and a new client certificate is needed for each instance of
  testing Dynamic Client Registration.  By default, Inferno will generate a
  new client certificate for each run of the Dynamic Client Registration test
  group.
- Signing certificate: the certificate used to issue and sign the client
  certificates.  This test kit includes a self-signed certificate
  authority, `InfernoCA.pem`, and its accompanying private key, `InfernoCA.key`,
  in `lib/udap_security/certs`.
  By default, Inferno will use this cert and private key to
  issue and sign it auto-generated client certs.  In the `lib/udap_security/certs`
  directory there is also a `generate_certs.sh` script that will
  regenerate the CA cert and its key as well as an example client cert and
  private key.

Testers may also provide their own client certificate(s) via the
test inputs.

In order for tests to pass, register the `InfernoCA.pem` file (if using
Inferno's default CA) OR your own signing certificate as a trusted CA with
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
