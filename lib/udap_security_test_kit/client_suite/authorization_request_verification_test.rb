require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'
require_relative 'client_descriptions'

module UDAPSecurityTestKit
  class UDAPClientAppLaunchAuthorizationRequestVerification < Inferno::Test
    include URLs

    id :udap_client_authorization_request_verification
    title 'Verify UDAP Authorization Requests'
    description %(
      Check that UDAP authorization requests made are conformant.
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

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@67',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@128',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@129'

    def client_suite_id
      return config.options[:endpoint_suite_id] if config.options[:endpoint_suite_id].present?

      UDAPSecurityTestKit::UDAPSecurityClientTestSuite.id
    end

    run do
      load_tagged_requests(AUTHORIZATION_TAG, UDAP_TAG)
      skip_if requests.blank?, 'No UDAP authorization requests made.'

      requests.each_with_index do |authorization_request, index|
        auth_code_request_params = MockUDAPServer.authorization_code_request_details(authorization_request)
        check_request_params(auth_code_request_params, index + 1)
      end

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid authorization requests detected. See messages for details.'
    end

    def check_request_params(params, request_num) # rubocop:disable Metrics/CyclomaticComplexity
      if params['response_type'] != 'code'
        add_message('error',
                    "Authorization request #{request_num} had an incorrect `response_type`: expected 'code', " \
                    "but got '#{params['response_type']}'")
      end
      if params['client_id'] != client_id
        add_message('error',
                    "Authorization request #{request_num} had an incorrect `client_id`: expected #{client_id}, " \
                    "but got '#{params['client_id']}'")
      end
      registration_body, _registration_header = JWT.decode(udap_registration_jwt, nil, false)
      if params['redirect_uri'].present?
        # must be a registered redirect_uri
        unless registration_body['redirect_uris']&.include?(params['redirect_uri'])
          add_message('error',
                      "Authorization request #{request_num} had an invalid `redirect_uri`: expected one of " \
                      "'#{registration_body['redirect_uris']&.join(', ')}', but got '#{params['redirect_uri']}'")
        end
      else
        # can only be one registered redirect_uri
        unless registration_body['redirect_uris']&.length == 1
          add_message('error',
                      "Authorization request #{request_num} had an invalid `redirect_uri`: expected one of " \
                      "'#{registration_body['redirect_uris']&.join(', ')}', but got none")
        end
      end

      if params['state'].blank?
        add_message('warning',
                    "Authorization request #{request_num} is missing the recommended `state` element")
      end

      nil
    end
  end
end
