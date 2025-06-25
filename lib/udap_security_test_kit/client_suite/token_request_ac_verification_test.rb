require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'client_descriptions'
require_relative 'client_options'
require_relative 'token_request_verification'

module UDAPSecurityTestKit
  class UDAPClientTokenRequestAuthorizationCodeVerification < Inferno::Test
    include URLs
    include TokenRequestVerification

    id :udap_client_token_request_ac_verification
    title 'Verify UDAP Authorization Code Token Requests'
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
                          'hl7.fhir.us.udap-security_1.0.0@140',
                          'hl7.fhir.us.udap-security_1.0.0@141',
                          'hl7.fhir.us.udap-security_1.0.0@142',
                          'hl7.fhir.us.udap-security_1.0.0@143',
                          'hl7.fhir.us.udap-security_1.0.0@145',
                          'hl7.fhir.us.udap-security_1.0.0@151',
                          'hl7.fhir.us.udap-security_1.0.0@152',
                          'hl7.fhir.us.udap-security_1.0.0@153',
                          'hl7.fhir.us.udap-security_1.0.0@154',
                          'hl7.fhir.us.udap-security_1.0.0@155',
                          'hl7.fhir.us.udap-security_1.0.0@156',
                          'hl7.fhir.us.udap-security_1.0.0@157',
                          'hl7.fhir.us.udap-security_1.0.0@158',
                          'hl7.fhir.us.udap-security_1.0.0@160',
                          'hl7.fhir.us.udap-security_1.0.0@161',
                          'hl7.fhir.us.udap-security_1.0.0@163',
                          'hl7.fhir.us.udap-security_1.0.0@165',
                          'hl7.fhir.us.udap-security_1.0.0@166',
                          'hl7.fhir.us.udap-security_1.0.0@167',
                          'hl7.fhir.us.udap-security_1.0.0@168',
                          'hl7.fhir.us.udap-security_1.0.0@169',
                          'hl7.fhir.us.udap-security_1.0.0@170',
                          'hl7.fhir.us.udap-security_1.0.0@171',
                          'hl7.fhir.us.udap-security_1.0.0@175',
                          'hl7.fhir.us.udap-security_1.0.0@177',
                          'hl7.fhir.us.udap-security_1.0.0@178',
                          'hl7.fhir.us.udap-security_1.0.0@179',
                          'hl7.fhir.us.udap-security_1.0.0@180',
                          'hl7.fhir.us.udap-security_1.0.0@185',
                          'hl7.fhir.us.udap-security_1.0.0@192',
                          'hl7.fhir.us.udap-security_1.0.0@193',
                          'hl7.fhir.us.udap-security_1.0.0@194',
                          'hl7.fhir.us.udap-security_1.0.0@195',
                          'hl7.fhir.us.udap-security_1.0.0@196',
                          'hl7.fhir.us.udap-security_1.0.0@197',
                          'hl7.fhir.us.udap-security_1.0.0@222',
                          'hl7.fhir.us.udap-security_1.0.0@232',
                          'hl7.fhir.us.udap-security_1.0.0@233',
                          'hl7.fhir.us.udap-security_1.0.0@234'

    def client_suite_id
      return config.options[:endpoint_suite_id] if config.options[:endpoint_suite_id].present?

      UDAPSecurityTestKit::UDAPSecurityClientTestSuite.id
    end

    run do
      load_tagged_requests(TOKEN_TAG, UDAP_TAG, AUTHORIZATION_CODE_TAG)
      skip_if requests.blank?, 'No UDAP token requests made.'
      load_tagged_requests(TOKEN_TAG, UDAP_TAG, REFRESH_TOKEN_TAG) # verify refresh_requests as well

      verify_token_requests(AUTHORIZATION_CODE_TAG)

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid token requests received. See messages for details.'
    end
  end
end
