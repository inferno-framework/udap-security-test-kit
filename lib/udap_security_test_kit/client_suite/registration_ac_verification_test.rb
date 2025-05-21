require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'registration_request_verification'

module UDAPSecurityTestKit
  class UDAPClientRegistrationAuthorizationCodeVerification < Inferno::Test
    include URLs
    include RegistrationRequestVerification

    id :udap_client_registration_ac_verification
    title 'Verify UDAP Authorization Code Registration'
    description %(
        During this test, Inferno will verify that the client's UDAP
        registration request is conformant.
      )
    input :udap_client_uri
    output :udap_registration_jwt

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@1',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@2',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@3',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@7',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@8',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@66',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@71',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@72',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@73',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@74',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@75',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@76',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@77',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@78',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@79',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@80',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@81',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@83',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@84',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@86',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@87',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@88',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@90',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@91',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@92',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@93',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@94',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@96',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@97',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@101',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@102',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@103',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@104'

    def client_suite_id
      return config.options[:endpoint_suite_id] if config.options[:endpoint_suite_id].present?

      UDAPSecurityTestKit::UDAPSecurityClientTestSuite.id
    end

    run do
      client_registration_requests = load_registration_requests_for_client_uri(udap_client_uri)
      skip_if client_registration_requests.empty?,
              "No UDAP Registration Requests made for client uri '#{udap_client_uri}'."

      verify_registration_request(AUTHORIZATION_CODE_TAG, client_registration_requests.last) # most recent if several

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid registration request. See messages for details.'
    end
  end
end
