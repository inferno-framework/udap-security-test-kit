require_relative 'endpoints/mock_udap_server/registration_endpoint'
require_relative 'endpoints/mock_udap_server/token_endpoint'
require_relative 'endpoints/echoing_fhir_responder'
require_relative 'urls'
require_relative 'client_suite/client_registration_group'
require_relative 'client_suite/client_access_group'

module UDAPSecurityTestKit
  class UDAPSecurityClientTestSuite < Inferno::TestSuite
    id :udap_security_client
    title 'UDAP Security Client'
    description File.read(File.join(__dir__, 'docs', 'udap_client_suite_description.md'))

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

    route(:get, UDAP_DISCOVERY_PATH, ->(_env) { MockUDAPServer.udap_server_metadata(id) })
    suite_endpoint :post, REGISTRATION_PATH, MockUDAPServer::RegistrationEndpoint
    suite_endpoint :post, TOKEN_PATH, MockUDAPServer::TokenEndpoint
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

    group do
      title 'UDAP Client Credentials Flow'
      description %(
        During these tests, the client will use the UDAP Client Credentials
        flow as specified in the [B2B section of the IG](https://hl7.org/fhir/us/udap-security/STU1/b2b.html)
        to access a FHIR API. Clients will register, obtain an access token,
        and use the access token when making a request to a FHIR API.
      )

      group from: :udap_client_registration
      group from: :udap_client_access
    end
  end
end
