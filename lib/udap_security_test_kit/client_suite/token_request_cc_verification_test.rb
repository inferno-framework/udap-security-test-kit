require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'client_descriptions'
require_relative 'client_options'
require_relative 'token_request_verification'

module UDAPSecurityTestKit
  class UDAPClientTokenRequestClientCredentialsVerification < Inferno::Test
    include URLs
    include TokenRequestVerification

    id :udap_client_token_request_cc_verification
    title 'Verify UDAP Client Credentials Token Requests'
    description %(
      Check that UDAP token requests are conformant.
    )

    input :client_id,
          title: 'Client Id',
          type: 'text',
          locked: true,
          description: INPUT_CLIENT_ID_DESCRIPTION_LOCKED
    input :udap_registration_jwt,
          title: 'Registered UDAP Software Statement',
          type: 'textarea',
          locked: 'true',
          description: INPUT_UDAP_REGISTRATION_JWT_DESCRIPTION_LOCKED
    output :udap_tokens

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@1',
                          'hl7.fhir.us.udap-security_1.0.0@2',
                          'hl7.fhir.us.udap-security_1.0.0@3',
                          'hl7.fhir.us.udap-security_1.0.0@7',
                          'hl7.fhir.us.udap-security_1.0.0@8',
                          'hl7.fhir.us.udap-security_1.0.0@67',
                          'hl7.fhir.us.udap-security_1.0.0@69',
                          'hl7.fhir.us.udap-security_1.0.0@186',
                          'hl7.fhir.us.udap-security_1.0.0@192',
                          'hl7.fhir.us.udap-security_1.0.0@193',
                          'hl7.fhir.us.udap-security_1.0.0@194',
                          'hl7.fhir.us.udap-security_1.0.0@195',
                          'hl7.fhir.us.udap-security_1.0.0@196',
                          'hl7.fhir.us.udap-security_1.0.0@197',
                          'hl7.fhir.us.udap-security_1.0.0@198',
                          'hl7.fhir.us.udap-security_1.0.0@202',
                          'hl7.fhir.us.udap-security_1.0.0@212',
                          'hl7.fhir.us.udap-security_1.0.0@214',
                          'hl7.fhir.us.udap-security_1.0.0@215',
                          'hl7.fhir.us.udap-security_1.0.0@223',
                          'hl7.fhir.us.udap-security_1.0.0@225',
                          'hl7.fhir.us.udap-security_1.0.0@226',
                          'hl7.fhir.us.udap-security_1.0.0@227',
                          'hl7.fhir.us.udap-security_1.0.0@228'

    def client_suite_id
      return config.options[:endpoint_suite_id] if config.options[:endpoint_suite_id].present?

      UDAPSecurityTestKit::UDAPSecurityClientTestSuite.id
    end

    run do
      load_tagged_requests(TOKEN_TAG, UDAP_TAG, CLIENT_CREDENTIALS_TAG)
      skip_if requests.blank?, 'No UDAP token requests made.'
      load_tagged_requests(TOKEN_TAG, UDAP_TAG, REFRESH_TOKEN_TAG) # verify refresh_requests as well (shouldn't be any)

      verify_token_requests(CLIENT_CREDENTIALS_TAG)

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid token requests received. See messages for details.'
    end
  end
end
