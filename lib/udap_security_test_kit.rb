require_relative 'udap_security_test_kit/authorization_code_group'
require_relative 'udap_security_test_kit/client_credentials_group'
require_relative 'udap_security_test_kit/version'

module UDAPSecurityTestKit
  class Suite < Inferno::TestSuite
    id :udap_security
    title 'UDAP Security'
    version VERSION
    description %(
      The User Data Access Protocol (UDAP) Security test kit verifies that systems correctly implement the
      [HL7 UDAP Security IG](http://hl7.org/fhir/us/udap-security/STU1/)
      for extending OAuth 2.0 using UDAP workflows.

      There are three steps to the UDAP workflow:
      1. Discovery
      2. Dynamic Client Registration
      3. Authorization & Authentication

      These steps are grouped by the OAuth2.0 flow being tested:
      1. Authorization Code flow, which supports
        [Consumer-Facing](https://hl7.org/fhir/us/udap-security/STU1/consumer.html) or [Business-to-Business (B2B)](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)
        use cases
      2. Client Credentials flow, which only supports the
      [B2B](https://hl7.org/fhir/us/udap-security/STU1/b2b.html) use case

      Testers may test one or both flows based on their system under test.
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

    # cert_file = File.read(File.join(File.dirname(__FILE__), 'udap_security_test_kit/certs/InfernoCA.pem'))

    # cert_file_route_handler = proc { [200, { 'Content-Type' => 'application/x-pem-file' }, [cert_file]] }

    # route(:get, '/inferno_ca.pem', cert_file_route_handler)

    resume_test_route :get, '/redirect' do |request|
      request.query_parameters['state']
    end

    links [
      {
        label: 'Report Issue',
        url: 'https://github.com/inferno-framework/udap-security-test-kit/issues'
      },
      {
        label: 'Open Source',
        url: 'https://github.com/inferno-framework/udap-security-test-kit'
      },
      {
        label: 'Download',
        url: 'https://github.com/inferno-framework/udap-security-test-kit/releases'
      }
    ]

    group from: :udap_authorization_code_group
    group from: :udap_client_credentials_group
  end
end
