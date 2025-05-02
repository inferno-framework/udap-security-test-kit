require_relative '../../urls'
require_relative '../../tags'
require_relative '../mock_udap_server'
require_relative '../../client_suite/oidc_jwks'

module UDAPSecurityTestKit
  module MockUDAPServer
    module UDAPTokenResponseCreation
      def make_udap_authorization_code_token_response # rubocop:disable Metrics/CyclomaticComplexity
        authorization_code = request.params[:code]
        client_id = MockUDAPServer.issued_token_to_client_id(authorization_code)
        software_statement = MockUDAPServer.udap_registration_software_statement(test_run.test_session_id)
        return unless udap_authenticated?(request.params[:client_assertion], software_statement)

        if MockUDAPServer.token_expired?(authorization_code)
          MockUDAPServer.update_response_for_expired_token(response, 'Authorization code')
          return
        end

        return if request.params[:code_verifier].present? && !udap_pkce_valid?(authorization_code)

        exp_min = 60
        response_body = {
          access_token: MockUDAPServer.client_id_to_token(client_id, exp_min),
          token_type: 'Bearer',
          expires_in: 60 * exp_min
        }

        launch_context =
          begin
            input_string = JSON.parse(result.input_json)&.find do |input|
              input['name'] == 'launch_context'
            end&.dig('value')
            JSON.parse(input_string) if input_string.present?
          rescue JSON::ParserError
            nil
          end
        additional_context = udap_requested_scope_context(udap_registered_scope(software_statement), authorization_code,
                                                          launch_context)

        response.body = additional_context.merge(response_body).to_json # response body values take priority
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.content_type = 'application/json'
        response.status = 200
      end

      def make_udap_refresh_token_response # rubocop:disable Metrics/CyclomaticComplexity
        refresh_token = request.params[:refresh_token]
        authorization_code = MockUDAPServer.refresh_token_to_authorization_code(refresh_token)
        client_id = MockUDAPServer.issued_token_to_client_id(authorization_code)
        software_statement = MockUDAPServer.udap_registration_software_statement(test_run.test_session_id)
        return unless udap_authenticated?(request.params[:client_assertion], software_statement)

        # no expiration checks for refresh tokens

        authorization_request = MockUDAPServer.authorization_request_for_code(authorization_code,
                                                                              test_run.test_session_id)
        if authorization_request.blank?
          MockUDAPServer.update_response_for_error(
            response,
            "no authorization request found for refresh token #{refresh_token}"
          )
          return
        end
        auth_code_request_inputs = MockUDAPServer.authorization_code_request_details(authorization_request)
        if auth_code_request_inputs.blank?
          MockUDAPServer.update_response_for_error(
            response,
            'invalid authorization request details'
          )
          return
        end

        exp_min = 60
        response_body = {
          access_token: MockUDAPServer.client_id_to_token(client_id, exp_min),
          token_type: 'Bearer',
          expires_in: 60 * exp_min
        }

        launch_context =
          begin
            input_string = JSON.parse(result.input_json)&.find do |input|
              input['name'] == 'launch_context'
            end&.dig('value')
            JSON.parse(input_string) if input_string.present?
          rescue JSON::ParserError
            nil
          end
        additional_context = udap_requested_scope_context(udap_registered_scope(software_statement), authorization_code,
                                                          launch_context)

        response.body = additional_context.merge(response_body).to_json # response body values take priority
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.content_type = 'application/json'
        response.status = 200
      end

      def make_udap_client_credential_token_response
        assertion = request.params[:client_assertion]
        client_id = MockUDAPServer.client_id_from_client_assertion(assertion)
        software_statement = MockUDAPServer.udap_registration_software_statement(test_run.test_session_id)
        return unless udap_authenticated?(request.params[:client_assertion], software_statement)

        exp_min = 60
        response_body = {
          access_token: MockUDAPServer.client_id_to_token(client_id, exp_min),
          token_type: 'Bearer',
          expires_in: 60 * exp_min
        }

        response.body = response_body.to_json
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.content_type = 'application/json'
        response.status = 200
      end

      def udap_authenticated?(assertion, software_statement)
        signature_error = MockUDAPServer.udap_token_signature_verification(assertion, software_statement)

        if signature_error.present?
          MockUDAPServer.update_response_for_error(response, signature_error)
          return false
        end

        true
      end

      def udap_requested_scope_context(requested_scopes, authorization_code, launch_context)
        context = launch_context.present? ? launch_context : {}
        scopes_list = requested_scopes&.split || []

        if scopes_list.include?('offline_access') || scopes_list.include?('online_access')
          context[:refresh_token] = MockUDAPServer.authorization_code_to_refresh_token(authorization_code)
        end

        context[:id_token] = udap_construct_id_token(scopes_list.include?('fhirUser')) if scopes_list.include?('openid')

        context
      end

      def udap_construct_id_token(include_fhir_user) # rubocop:disable Metrics/CyclomaticComplexity
        client_id = JSON.parse(result.input_json)&.find do |input|
          input['name'] == 'client_id'
        end&.dig('value')
        fhir_user_relative_reference = JSON.parse(result.input_json)&.find do |input|
          input['name'] == 'fhir_user_relative_reference'
        end&.dig('value')

        subject_id = if fhir_user_relative_reference.present?
                       fhir_user_relative_reference.downcase.gsub('/', '-')
                     else
                       SecureRandom.uuid
                     end

        claims = {
          iss: client_fhir_base_url,
          sub: subject_id,
          aud: client_id,
          exp: 1.year.from_now.to_i,
          iat: Time.now.to_i
        }
        if include_fhir_user && fhir_user_relative_reference.present?
          claims[:fhirUser] = "#{client_fhir_base_url}/#{fhir_user_relative_reference}"
        end

        algorithm = 'RS256'
        private_key = OIDCJWKS.jwks
          .select { |key| key[:key_ops]&.include?('sign') }
          .select { |key| key[:alg] == algorithm }
          .first

        JWT.encode claims, private_key.signing_key, algorithm, { alg: algorithm, kid: private_key.kid, typ: 'JWT' }
      end

      def udap_pkce_valid?(authorization_code)
        authorization_request = MockUDAPServer.authorization_request_for_code(authorization_code,
                                                                              test_run.test_session_id)
        if authorization_request.blank?
          MockUDAPServer.update_response_for_error(
            response,
            "Could not check code_verifier: no authorization request found that returned code #{authorization_code}"
          )
          return false
        end
        auth_code_request_inputs = MockUDAPServer.authorization_code_request_details(authorization_request)
        if auth_code_request_inputs.blank?
          MockUDAPServer.update_response_for_error(
            response,
            "Could not check code_verifier: invalid authorization request details for code #{authorization_code}"
          )
          return false
        end

        verifier = request.params[:code_verifier]
        challenge = auth_code_request_inputs&.dig('code_challenge')
        method = auth_code_request_inputs&.dig('code_challenge_method')
        MockUDAPServer.pkce_valid?(verifier, challenge, method, response)
      end

      def udap_registered_scope(software_statement_jwt)
        claims, _headers = begin
          JWT.decode(software_statement_jwt, nil, false)
        rescue StandardError
          return nil
        end

        claims['scope']
      end
    end
  end
end
