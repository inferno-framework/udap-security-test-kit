require_relative 'udap_security_test_kit/client_suite'
require_relative 'udap_security_test_kit/authorization_code_group'
require_relative 'udap_security_test_kit/client_credentials_group'
require_relative 'udap_security_test_kit/redirect_uri'
require_relative 'udap_security_test_kit/metadata'

module UDAPSecurityTestKit
  class Suite < Inferno::TestSuite
    id :udap_security
    title 'UDAP Security Server'
    description %(
      The User Data Access Protocol (UDAP) Security test kit verifies that systems correctly implement the
      [HL7 UDAP Security IG](http://hl7.org/fhir/us/udap-security/STU1/)
      for extending OAuth 2.0 using UDAP workflows.

      There are three steps to the UDAP workflow:
      1. Discovery
      2. Dynamic Client Registration
      3. Authorization & Authentication

      In this test suite, Inferno acts as a mock UDAP client to test *server conformance* to the HL7 UDAP IG. Tests are
      grouped according to the OAuth2.0 flow used in the authorization and authentication step:
      1. Authorization Code flow, which supports
        [Consumer-Facing](https://hl7.org/fhir/us/udap-security/STU1/consumer.html) or [Business-to-Business (B2B)](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)
        use cases
      2. Client Credentials flow, which only supports the
      [B2B](https://hl7.org/fhir/us/udap-security/STU1/b2b.html) use case

      Testers may test one or both flows based on their system under test.

      This test suite does NOT assess [Tiered OAuth for User Authentication](https://hl7.org/fhir/us/udap-security/STU1/user.html)
      (which is not a required capability).
    )

    requirement_sets(
      {
        identifier: 'hl7.fhir.us.udap-security_1.0.0',
        title: 'Security for Scalable Registration, Authentication, and Authorization (UDAP)',
        actor: 'Server'
      }
    )

    input_instructions %(
      This menu will execute tests for both OAuth flows.

      **Discovery Tests**

      #{DiscoveryGroup.discovery_group_input_instructions}

      **Dynamic Client Registration Tests**

      A single logical UDAP client cannot register itself for both `authorization_code` and `client_credentials` grant
      types.
      Inferno will therefore represent a distinct logical client for each OAuth flow and requires a unique issuer URI
      value for each flow's registration step.
      If the provided client certificate has more than one URI entry in its Subject Alternative Name (SAN) extension,
      client certificates may be reused for each flow. If not, each auth flow will require its own client certificate.

      Please refer to the [UDAP Dynamic Client Registration IG Section 3.1](https://hl7.org/fhir/us/udap-security/STU1/registration.html#software-statement)
      entries on `grant_type` and `iss` claims for more details.
    )

    resume_test_route :get, '/redirect' do |request|
      request.query_parameters['state']
    end

    config options: {
      redirect_uri: UDAPSecurityTestKit::UDAP_REDIRECT_URI
    }

    links [
      {
        type: 'source_code',
        label: 'Open Source',
        url: 'https://github.com/inferno-framework/udap-security-test-kit/'
      },
      {
        type: 'report_issue',
        label: 'Report Issue',
        url: 'https://github.com/inferno-framework/udap-security-test-kit/issues/'
      },
      {
        type: 'download',
        label: 'Download',
        url: 'https://github.com/inferno-framework/udap-security-test-kit/releases/'
      },
      {
        type: 'ig',
        label: 'Implementation Guide',
        url: 'https://hl7.org/fhir/us/udap-security/STU1/'
      }
    ]

    group from: :udap_authorization_code_group
    group from: :udap_client_credentials_group
  end
end
