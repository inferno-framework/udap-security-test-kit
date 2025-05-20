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

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@66',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@67',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@69',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@140',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@141',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@142',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@143',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@145',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@151',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@152',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@153',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@154',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@155',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@156',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@157',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@158',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@160',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@161',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@163',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@165',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@166',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@167',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@168',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@169',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@170',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@171',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@175',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@177',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@178',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@179',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@180',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@185',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@192',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@193',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@194',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@195',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@196',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@197',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@232',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@233',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@234'

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
