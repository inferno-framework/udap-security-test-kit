require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'registration_request_verification'

module UDAPSecurityTestKit
  class UDAPClientRegistrationClientCredentialsVerification < Inferno::Test
    include URLs
    include RegistrationRequestVerification

    id :udap_client_registration_cc_verification
    title 'Verify UDAP Client Credentials Registration'
    description %(
        During this test, Inferno will verify that the client's UDAP
        registration request is conformant.
      )
    input :udap_client_uri
    output :udap_registration_jwt

    def client_suite_id
      return config.options[:endpoint_suite_id] if config.options[:endpoint_suite_id].present?

      UDAPSecurityTestKit::UDAPSecurityClientTestSuite.id
    end

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@1',
                          'hl7.fhir.us.udap-security_1.0.0@2',
                          'hl7.fhir.us.udap-security_1.0.0@3',
                          'hl7.fhir.us.udap-security_1.0.0@7',
                          'hl7.fhir.us.udap-security_1.0.0@8',
                          'hl7.fhir.us.udap-security_1.0.0@66',
                          'hl7.fhir.us.udap-security_1.0.0@71',
                          'hl7.fhir.us.udap-security_1.0.0@72',
                          'hl7.fhir.us.udap-security_1.0.0@73',
                          'hl7.fhir.us.udap-security_1.0.0@74',
                          'hl7.fhir.us.udap-security_1.0.0@75',
                          'hl7.fhir.us.udap-security_1.0.0@76',
                          'hl7.fhir.us.udap-security_1.0.0@77',
                          'hl7.fhir.us.udap-security_1.0.0@78',
                          'hl7.fhir.us.udap-security_1.0.0@79',
                          'hl7.fhir.us.udap-security_1.0.0@80',
                          'hl7.fhir.us.udap-security_1.0.0@81',
                          'hl7.fhir.us.udap-security_1.0.0@83',
                          'hl7.fhir.us.udap-security_1.0.0@85',
                          'hl7.fhir.us.udap-security_1.0.0@86',
                          'hl7.fhir.us.udap-security_1.0.0@87',
                          'hl7.fhir.us.udap-security_1.0.0@92',
                          'hl7.fhir.us.udap-security_1.0.0@95',
                          'hl7.fhir.us.udap-security_1.0.0@96',
                          'hl7.fhir.us.udap-security_1.0.0@97',
                          'hl7.fhir.us.udap-security_1.0.0@101',
                          'hl7.fhir.us.udap-security_1.0.0@102',
                          'hl7.fhir.us.udap-security_1.0.0@103',
                          'hl7.fhir.us.udap-security_1.0.0@104'

    run do
      client_registration_requests = load_registration_requests_for_client_uri(udap_client_uri)
      skip_if client_registration_requests.empty?,
              "No UDAP Registration Requests made for client uri '#{udap_client_uri}'."

      verify_registration_request(CLIENT_CREDENTIALS_TAG, client_registration_requests.last) # most recent if several

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid registration request. See messages for details.'
    end
  end
end
