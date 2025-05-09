require_relative '../../tags'
require_relative '../mock_udap_server'

module UDAPSecurityTestKit
  module MockUDAPServer
    module UDAPIntrospectionResponseCreation
      def make_udap_introspection_response # rubocop:disable Metrics/CyclomaticComplexity
        target_token = request.params[:token]
        introspection_inactive_response_body = { active: false }

        return introspection_inactive_response_body if MockUDAPServer.token_expired?(target_token)

        token_requests = Inferno::Repositories::Requests.new.tagged_requests(test_run.test_session_id, [TOKEN_TAG])
        original_response_body = nil
        original_token_request = token_requests.find do |request|
          next unless request.status == 200

          original_response_body = JSON.parse(request.response_body)
          original_response_body['access_token'] == target_token
        end
        return introspection_inactive_response_body unless original_token_request.present?

        decoded_token = MockUDAPServer.decode_token(target_token)
        introspection_active_response_body = {
          active: true,
          client_id: decoded_token['client_id'],
          exp: decoded_token['expiration']
        }
        original_response_body.each do |element, value|
          next if ['access_token', 'refresh_token', 'token_type', 'expires_in'].include?(element)
          next if introspection_active_response_body.key?(element)

          introspection_active_response_body[element] = value
        end
        unless introspection_active_response_body.key?('scope')
          introspection_active_response_body['scope'] = requested_scope(original_token_request)
        end
        if original_response_body.key?('id_token')
          user_claims, _header = JWT.decode(original_response_body['id_token'], nil, false)
          introspection_active_response_body['iss'] = user_claims['iss']
          introspection_active_response_body['sub'] = user_claims['sub']
          introspection_active_response_body['fhirUser'] = user_claims['fhirUser'] if user_claims['fhirUser'].present?
        end

        introspection_active_response_body
      end

      def requested_scope(token_request)
        # token request

        original_request_body = MockUDAPServer.token_request_details(token_request)
        return original_request_body['scope'] if original_request_body['scope'].present?

        # authorization request
        authorization_request = MockUDAPServer.authorization_request_for_code(original_request_body['code'],
                                                                              test_run.test_session_id)
        auth_code_request_inputs = MockUDAPServer.authorization_code_request_details(authorization_request)
        return auth_code_request_inputs['scope'] if auth_code_request_inputs&.dig('scope').present?

        # registration request
        registered_software_statement = MockUDAPServer.udap_registration_software_statement(test_run.test_session_id)
        if registered_software_statement.present?
          registration_body, _registration_header = JWT.decode(registered_software_statement, nil, false)
          return registration_body['scope'] if registration_body['scope'].present?
        end

        nil
      end
    end
  end
end
