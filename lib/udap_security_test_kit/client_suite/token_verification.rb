module UDAPSecurityTestKit
  module TokenVerification
    def verify_token_requests(oauth_flow)
      registration_token =
        begin
          JWT::EncodedToken.new(udap_registration_jwt)
        rescue StandardError => e
          assert false, "Registration request parsing failed: #{e}"
        end

      jti_list = []
      token_list = []
      requests.each_with_index do |token_request, index|
        request_params = URI.decode_www_form(token_request.request_body).to_h
        check_request_params(oauth_flow, request_params, index + 1)
        check_client_assertion(oauth_flow, request_params['client_assertion'], index + 1, jti_list, registration_token,
                               client_id, token_request.created_at)
        token_list << extract_token_from_response(token_request)
      end

      output udap_tokens: token_list.compact.join("\n")
    end

    def check_request_params(oauth_flow, params, request_num)
      if params['grant_type'] != oauth_flow
        add_message('error',
                    "Token request #{request_num} had an incorrect `grant_type`: expected '#{oauth_flow}', " \
                    "but got '#{params['grant_type']}'")
      end
      if params['client_assertion_type'] != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        add_message('error',
                    "Token request #{request_num} had an incorrect `client_assertion_type`: " \
                    "expected 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', " \
                    "but got '#{params['client_assertion_type']}'")
      end
      unless params['udap'].to_s == '1'
        add_message('error',
                    "Token request #{request_num} had an incorrect `udap`: " \
                    "expected '1', " \
                    "but got '#{params['udap']}'")
      end

      check_authorization_code_request_params(params, request_num) if oauth_flow == AUTHORIZATION_CODE_TAG

      nil
    end

    def check_authorization_code_request_params(params, request_num)
      if params['code'].present?

        authorization_request = MockUDAPServer.authorization_request_for_code(params['code'], test_session_id)

        if authorization_request.present?
          authorization_body = MockUDAPServer.authorization_code_request_details(authorization_request)

          if params['redirect_uri'] != authorization_body['redirect_uri']
            add_message('error', "Authorization code token request #{request_num} included an incorrect " \
                                 "`redirect_uri` value: expected '#{authorization_body['redirect_uri']} " \
                                 "but got '#{params['redirect_uri']}'")
          end

          return unless params['code_verifier'].present? # optional in UDAP

          pkce_error = MockUDAPServer.pkce_error(params['code_verifier'],
                                                 authorization_body['code_challenge'],
                                                 authorization_body['code_challenge_method'])
          if pkce_error.present?
            add_message('error', 'Error performing pkce verification on the `code_verifier` value in ' \
                                 "authorization code token request #{request_num}: #{pkce_error}")
          end
        else
          add_message('error', "Authorization code token request #{request_num} included a code not " \
                               "issued during this test session: '#{params['code']}'")
        end
      else
        add_message('error', "Authorization code token request #{request_num} missing a `code`")
      end
    end

    def check_client_assertion(oauth_flow, assertion, request_num, jti_list, registration_token, registered_client_id,
                               request_time)
      decoded_token =
        begin
          JWT::EncodedToken.new(assertion)
        rescue StandardError => e
          add_message('error', "Token request #{request_num} contained an invalid client assertion jwt: #{e}")
          nil
        end

      return unless decoded_token.present?

      # header checked with signature
      check_jwt_payload(oauth_flow, decoded_token.payload, request_num, jti_list, registered_client_id, request_time)
      check_jwt_signature(decoded_token, registration_token, request_num)
    end

    def check_jwt_payload(oauth_flow, claims, request_num, jti_list, registered_client_id, request_time) # rubocop:disable Metrics/CyclomaticComplexity
      if claims['iss'] != registered_client_id
        add_message('error', "client assertion jwt on token request #{request_num} has an incorrect `iss` claim: " \
                             "expected '#{registered_client_id}', got '#{claims['iss']}'")
      end

      if claims['sub'] != registered_client_id
        add_message('error', "client assertion jwt on token request #{request_num} has an incorrect `sub` claim: " \
                             "expected '#{registered_client_id}', got '#{claims['sub']}'")
      end

      if claims['aud'] != client_token_url
        add_message('error', "client assertion jwt on token request #{request_num} has an incorrect `aud` claim: " \
                             "expected '#{client_token_url}', got '#{claims['aud']}'")
      end

      MockUDAPServer.check_jwt_timing(claims['iat'], claims['exp'], request_time)

      if claims['jti'].blank?
        add_message('error', "client assertion jwt on token request #{request_num} is missing the `jti` claim.")
      elsif jti_list.include?(claims['jti'])
        add_message('error', "client assertion jwt on token request #{request_num} has a `jti` claim that was " \
                             "previouly used: '#{claims['jti']}'.")
      else
        jti_list << claims['jti']
      end

      return unless oauth_flow == CLIENT_CREDENTIALS_TAG

      if claims['extensions'].present?
        if claims['extensions'].is_a?(Hash)
          check_b2b_auth_extension(claims.dig('extensions', 'hl7-b2b'), request_num)
        else
          add_message('error', "client assertion jwt on token request #{request_num} has an `extensions` claim that " \
                               'is not a json object.')
        end
      else
        add_message('error', "client assertion jwt on token request #{request_num} missing the `hl7-b2b` extension.")
      end
    end

    def check_b2b_auth_extension(b2b_auth, request_num)
      if b2b_auth.blank?
        add_message('error', "client assertion jwt on token request #{request_num} missing the `hl7-b2b` extension.")
        return
      end

      if b2b_auth['version'].blank?
        add_message('error', "the `hl7-b2b` extension on client assertion jwt on token request #{request_num} is " \
                             'missing the required `version` key.')
      elsif b2b_auth['version'].to_s != '1'
        add_message('error', "the `hl7-b2b` extension on client assertion jwt on token request #{request_num} has an " \
                             "incorrect `version` value: expected `1`, got #{b2b_auth['version']}.")
      end

      if b2b_auth['organization_id'].blank?
        add_message('error', "the `hl7-b2b` extension on client assertion jwt on token request #{request_num} is " \
                             'missing the required `organization_id` key.')
      else
        begin
          URI.parse(b2b_auth['organization_id'])
        rescue URI::InvalidURIError
          add_message('error', 'the `organization_id` key in the `hl7-b2b` extension on client assertion jwt on ' \
                               "token request #{request_num} is not a valid URI.")
        end
      end

      if b2b_auth['purpose_of_use'].blank?
        add_message('error', "the `hl7-b2b` extension on client assertion jwt on token request #{request_num} is " \
                             'missing the required `purpose_of_use` key.')
      end

      nil
    end

    def check_jwt_signature(encoded_token, registration_token, request_num)
      error = MockUDAPServer.udap_token_signature_verification(encoded_token.jwt, registration_token.jwt)

      return unless error.present?

      add_message('error', "Signature validation failed on token request #{request_num}: #{error}")
    end

    def extract_token_from_response(request)
      return unless request.status == 200

      JSON.parse(request.response_body)&.dig('access_token')
    rescue StandardError
      nil
    end
  end
end
