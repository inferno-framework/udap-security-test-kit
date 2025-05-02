## Overview

The UDAP Security Client Test Suite verifies the conformance of
client systems to the STU 1.0.0 version of the HL7® FHIR®
[Security for Scalable Registration, Authentication, and Authorization (UDAP Security) FHIR IG](https://hl7.org/fhir/us/udap-security/STU1/).

## Scope

The UDAP Security Client Test Suite verifies that systems correctly implement
the [UDAP Security IG](https://hl7.org/fhir/us/udap-security/STU1/)
for authorizating and/or authenticating with a server in order to gain 
access to HL7® FHIR® APIs. The suite contains options for testing clients that follow the
- Authorization Code flow for [consumer facing](https://hl7.org/fhir/us/udap-security/STU1/consumer.html)
  or [Business-to-Business](https://hl7.org/fhir/us/udap-security/STU1/b2b.html) access.
- Client Credentials flow for [Business-to-Business](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)
  access.

These tests are a **DRAFT** intended to allow implementers to perform
preliminary checks of their systems against UDAP Security IG
and [provide feedback](https://github.com/inferno-framework/udap-security-test-kit/issues)
on the tests. Future versions of these tests may verify other
requirements and may change the test verification logic.

## Test Methodology

For these tests Inferno simulates a UDAP server that supports both the authorization code
and the client credentials flows. In both cases, testers will
1. Provide to Inferno the client URI with which they will register their system.
2. Make a dynamic registration request to Inferno using the provided client URI
   and including the X.509 certificate used to sign the registeration and subsequent
   token requests which must also have the client URI as a Subject Alternative Name (SAN)
   value in the certificate.
3. Obtain an access token with a request using the client Id returned during registration
   and signed using same X.509 certificate supplied during registration.
4. Use that access token on a FHIR API request.

The simulated UDAP server is relatively permissive in the sense that it will often
provide successful responses even when the request is not conformant. When
requesting tokens, Inferno will return an access token as long as it can find
the client id and the signature is valid. This allows incomplete systems to
run the tests. However, these non-conformant requests will be flagged by
the tests as failures so that systems will not pass the tests without being
fully conformant.

## Running the Tests

### Quick Start

The following inputs must be provided by the tester at a minimum to execute
any tests in this suite:
1. **UDAP Client URI**: The UDAP Client URI that will be used to register with
   Inferno's simulated UDAP server.

The *Additional Inputs* section below describes options available to customize
the behavior of Inferno's server simulation.

### Demonstration

To try out these tests without a UDAP client implementation, these tests can be exercised
using the UDAP Security server test suite and a simple HTTP request generator. The following
steps use [Postman](https://www.postman.com/) to generate the access request using 
[this collection](https://github.com/inferno-framework/udap-security-test-kit/blob/main/lib/udap_security_test_kit/docs/demo/FHIR%20Request.postman_collection.json).
Install the app and import the collection before following these steps.

1. Start an instance of the UDAP Security Client test suite and choose either option: *Authorization Code*,
   or *Client Credentials* flow. Remember your choice for use later.
1. From the drop down in the upper left, select preset "Demo: Run Against the UDAP Security Server Suite".
1. Click the "RUN ALL TESTS" button in the upper right and click "SUBMIT"
1. In a new tab, start an instance of the UDAP Security Server Test Suite
1. From the drop down in the upper left, select preset "Demo: Run Against the UDAP Security Client Suite"
1. Select the test group corresponding to your choice in step 1: **1** for *Authorization Code* and **2**
   for *Client Credentials*. Click the "RUN ALL TESTS" button in the upper right, and click "SUBMIT".
1. If testing the *Authorization Code* flow, click the link to authorize with the server.
1. In the Client suite tab, click the link in the wait dialog to continue the tests.
1. In the Server suite tab, find the access token to use for the data access request by opening
   test **1.3.03** or **2.3.01** OAuth token exchange request succeeds when supplied correct information,
   click on the "REQUESTS" tab, clicking on the "DETAILS" button, and expanding the "Response Body".
   Copy the "access_token" value, which will be a ~100 character string of letters and numbers (e.g., eyJjbGllbnRfaWQiOiJzbWFydF9jbGllbnRfdGVzdF9kZW1vIiwiZXhwaXJhdGlvbiI6MTc0MzUxNDk4Mywibm9uY2UiOiJlZDI5MWIwNmZhMTE4OTc4In0)
1. Open Postman and open the "FHIR Request" Collection. Click the "Variables" tab and add the
   copied access token as the current value of the `bearer_token` variable. Also update the
   `base_url` value for where the test is running (see details on the "Overview" tab).
   Save the collection.
1. Select the "Patient Read" request and click "Send". A FHIR Patient resource should be returned.
1. Return to the client tests and click the link to continue and complete the tests.

The client tests should pass. On the server side some of the registration tests will fail. This is
expected as the Server tests make several intentionally invalid token requests. Inferno's simulated UDAP
server responds successfully to those requests when the client id can be identified, but flags them as
not conformant causing these expected failures. Because responding successfully to non-conformant
registration requests is itself not conformant there are corresponding failures on the server test.

### Additional Inputs

#### Inputs Controlling Token Responses

The UDAP simulation incorporates some aspects of SMART App launch including its approach to
[context data](https://hl7.org/fhir/smart-app-launch/STU2.2/scopes-and-launch-context.html)
in token responses during the authorization code flow.
Inferno's SMART simulation does not include the details needed to populate
these details into the token response when requested by apps using scopes.
If the tested app needs and will request these details, the tester must provide them for Inferno
to respond with using the following inputs:
- **Launch Context** (available for all *SMART App Launch* clients): Testers can provide a JSON
  array for Inferno to use as the base for building a token response on. This can include
  keys like `"patient"` when the `launch/patient` scope will be requested. Note that when keys that Inferno
  also populates (e.g. `access_token` or `id_token`) are included, the Inferno value will be returned.
- **FHIR User Relative Reference** (available for all *SMART App Launch* clients): Testers
  can provide a FHIR relative reference (`<resource type>/<id>`) for the FHIR user record
  to return with the `id_token` when the `openid` and `fhirUser` scopes are requested. If populated,
  include the corresponding resource in the **Available Resources** input (See the "Inputs
  Controlling FHIR Responses" section) so that it can be accessed via FHIR read.

#### Inputs Controlling FHIR Responses
The focus of this test kit is on the auth protocol, so the simulated FHIR server implemented
in this test suite is very simple. It will respond to any FHIR request with either:
  - A resource from a tester-provided Bundle in the **Available Resources** input
    if the request is a read matching a resource type and id found in the Bundle.
  - Otherwise, the contents of the **Default FHIR Response** input, if provided.
  - Otherwise, an OperationOutcome indicating no response was available.

The two inputs that control these response include:
- **Available Resources**: A FHIR Bundle of resources to make available via the
  simulated FHIR sever. Each entry must contain a resource with the id element
  populated. Each instance present will be available for retrieval from Inferno
  at the endpoint: `<fhir-base>/<resource type>/<instance id>`. These will only
  be available through the read interaction.
- **FHIR Response to Echo**: A static FHIR JSON body for Inferno to return for all FHIR requests
  not covered by reads of instances in the **Available Resources** input. In this case,
  the simulation is a simple echo and Inferno does not check that the response is
  appropriate for the request made.

## Current Limitations

This test kit is still in draft form and does not test all of the requirements and features
described in the UDAP Security IG for clients.

The following sections list known gaps and limitations.

### SMART Scope Checking and Fulfilment

These tests do not verify any details about scopes, including that the
- Requested scopes are conformant, such as that they have a valid format and are consistent
  between authorization and refresh token requests.
- Provided **Launch Context** input fullfils the requested data context scopes.
- Access performed is allowed by the requested scope.

### UDAP Server Simulation Limitations

This test suite contains a simulation of a UDAP server which is not fully
general and not all conformant clients may be able to interact with it. One
specific example is that the UDAP configuration metadata available at
`.well-known/udap` for the simulated server is fixed and cannot be changed by
testers at this time. Despite the current limitations, the intention is for Inferno to
support a variety of conformant choices, so please report issues that prevent conformant
systems from passing in the [github repository's issues page](https://github.com/inferno-framework/udap-security-test-kit/issues/).

### FHIR Server Simulation Limitations

The FHIR server simulation used to support clients in demonstrating their ability to access
FHIR APIs using access tokens obtained using the SMART flows is very limited. Testers are currently
able to provide a list of resources to be read and a single static response that will be echoed for any
other FHIR request made. While Inferno will never implement a fully general FHIR server simulation,
additional options, such as may be added in the future based on community feedback.