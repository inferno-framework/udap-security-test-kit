require_relative 'endpoints/mock_udap_server/registration'
require_relative 'endpoints/mock_udap_server/token'
require_relative 'endpoints/echoing_fhir_responder'
require_relative 'urls'
require_relative 'client_suite/client_registration_group'
require_relative 'client_suite/client_access_group'

module UDAPSecurityTestKit
  class UDAPSecurityClientTestSuite < Inferno::TestSuite
    id :udap_security_client
    title 'UDAP Security Client'
    description %(
      The User Data Access Protocol (UDAP) Security Client test kit verifies that client systems correctly
      implement the [STU 1 version of HL7 UDAP Security IG](http://hl7.org/fhir/us/udap-security/STU1/)
      for extending OAuth 2.0 using [UDAP workflows](https://www.udap.org/index.html).

      There are three steps to the UDAP workflow:
      1. Discovery
      2. Dynamic Client Registration
      3. Authorization & Authentication

      In this test suite, Inferno acts as a mock UDAP server to test *client conformance* to the HL7 UDAP IG.
      Currently, only the [B2B](https://hl7.org/fhir/us/udap-security/STU1/b2b.html) Client Credentials flow is tested.
    )

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
      }
    ]

    route(:get, UDAP_DISCOVERY_PATH, MockUdapServer.method(:udap_server_metadata))
    suite_endpoint :post, REGISTRATION_PATH, MockUdapServer::RegistrationEndpoint
    suite_endpoint :post, TOKEN_PATH, MockUdapServer::TokenEndpoint
    suite_endpoint :get, FHIR_PATH, EchoingFHIRResponderEndpoint
    suite_endpoint :post, FHIR_PATH, EchoingFHIRResponderEndpoint
    suite_endpoint :put, FHIR_PATH, EchoingFHIRResponderEndpoint
    suite_endpoint :delete, FHIR_PATH, EchoingFHIRResponderEndpoint
    suite_endpoint :get, "#{FHIR_PATH}/:one", EchoingFHIRResponderEndpoint
    suite_endpoint :post, "#{FHIR_PATH}/:one", EchoingFHIRResponderEndpoint
    suite_endpoint :put, "#{FHIR_PATH}/:one", EchoingFHIRResponderEndpoint
    suite_endpoint :delete, "#{FHIR_PATH}/:one", EchoingFHIRResponderEndpoint
    suite_endpoint :get, "#{FHIR_PATH}/:one/:two", EchoingFHIRResponderEndpoint
    suite_endpoint :post, "#{FHIR_PATH}/:one/:two", EchoingFHIRResponderEndpoint
    suite_endpoint :put, "#{FHIR_PATH}/:one/:two", EchoingFHIRResponderEndpoint
    suite_endpoint :delete, "#{FHIR_PATH}/:one/:two", EchoingFHIRResponderEndpoint
    suite_endpoint :get, "#{FHIR_PATH}/:one/:two/:three", EchoingFHIRResponderEndpoint
    suite_endpoint :post, "#{FHIR_PATH}/:one/:two/:three", EchoingFHIRResponderEndpoint
    suite_endpoint :put, "#{FHIR_PATH}/:one/:two/:three", EchoingFHIRResponderEndpoint
    suite_endpoint :delete, "#{FHIR_PATH}/:one/:two/:three", EchoingFHIRResponderEndpoint

    resume_test_route :get, RESUME_PASS_PATH do |request|
      request.query_parameters['token']
    end

    resume_test_route :get, RESUME_FAIL_PATH, result: 'fail' do |request|
      request.query_parameters['token']
    end

    group from: :udap_client_registration
    group from: :udap_client_access
  end
end
