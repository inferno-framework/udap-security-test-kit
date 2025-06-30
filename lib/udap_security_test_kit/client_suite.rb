require_relative 'endpoints/mock_udap_server/registration_endpoint'
require_relative 'endpoints/mock_udap_server/authorization_endpoint'
require_relative 'endpoints/mock_udap_server/token_endpoint'
require_relative 'endpoints/mock_udap_server/introspection_endpoint'
require_relative 'endpoints/echoing_fhir_responder_endpoint'
require_relative 'urls'
require_relative 'client_suite/registration_ac_group'
require_relative 'client_suite/registration_cc_group'
require_relative 'client_suite/access_ac_group'
require_relative 'client_suite/access_cc_group'
require_relative 'visual_inspection_and_attestation/client_attestation_group'

module UDAPSecurityTestKit
  class UDAPSecurityClientTestSuite < Inferno::TestSuite
    id :udap_security_client
    title 'UDAP Security Client'
    description File.read(File.join(__dir__, 'docs', 'udap_client_suite_description.md'))

    requirement_sets(
      {
        identifier: 'hl7.fhir.us.udap-security_1.0.0',
        title: 'Security for Scalable Registration, Authentication, and Authorization (UDAP)',
        actor: 'Client'
      }
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
      },
      {
        type: 'ig',
        label: 'Implementation Guide',
        url: 'https://hl7.org/fhir/us/udap-security/STU1/'
      }
    ]

    suite_option :client_type,
                 title: 'UDAP Client Type',
                 list_options: [
                   {
                     label: 'UDAP Authorization Code Client',
                     value: UDAPClientOptions::UDAP_AUTHORIZATION_CODE
                   },
                   {
                     label: 'UDAP Client Credentials Client',
                     value: UDAPClientOptions::UDAP_CLIENT_CREDENTIALS
                   }
                 ]

    route(:get, UDAP_DISCOVERY_PATH, ->(_env) { MockUDAPServer.udap_server_metadata(id) })
    route(:get, OIDC_DISCOVERY_PATH, ->(_env) { MockUDAPServer.openid_connect_metadata(id) })
    route(
      :get,
      OIDC_JWKS_PATH,
      ->(_env) { [200, { 'Content-Type' => 'application/json' }, [OIDCJWKS.jwks_json]] }
    )

    suite_endpoint :post, REGISTRATION_PATH, MockUDAPServer::RegistrationEndpoint
    suite_endpoint :get, AUTHORIZATION_PATH, MockUDAPServer::AuthorizationEndpoint
    suite_endpoint :post, AUTHORIZATION_PATH, MockUDAPServer::AuthorizationEndpoint
    suite_endpoint :post, INTROSPECTION_PATH, MockUDAPServer::IntrospectionEndpoint
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

    group from: :udap_client_registration_ac,
          required_suite_options: {
            client_type: UDAPClientOptions::UDAP_AUTHORIZATION_CODE
          }
    group from: :udap_client_registration_cc,
          required_suite_options: {
            client_type: UDAPClientOptions::UDAP_CLIENT_CREDENTIALS
          }
    group from: :udap_client_access_ac,
          required_suite_options: {
            client_type: UDAPClientOptions::UDAP_AUTHORIZATION_CODE
          }
    group from: :udap_client_access_cc,
          required_suite_options: {
            client_type: UDAPClientOptions::UDAP_CLIENT_CREDENTIALS
          }
    
    group from: :udap_client_v100_visual_inspection_and_attestation
  end
end
