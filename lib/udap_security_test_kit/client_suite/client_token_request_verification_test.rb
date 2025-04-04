require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'

module UDAPSecurityTestKit
  class UDAPClientTokenRequestVerification < Inferno::Test
    include URLs

    id :udap_client_token_request_verification
    title 'Verify UDAP Token Requests'
    description %(
      Check that UDAP token requests are conformant.
    )

    output :udap_demonstrated
    output :udap_tokens

    run do
      load_tagged_requests(REGISTRATION_TAG, UDAP_TAG)
      output udap_demonstrated: requests.present? ? 'Yes' : 'No'
      omit_if requests.blank?, 'UDAP Authentication not demonstrated as a part of this test session.'
      registration_request = requests.last
      registration_assertion = MockUDAPServer.parsed_request_body(registration_request)['software_statement']
      registration_token =
        begin
          JWT::EncodedToken.new(registration_assertion)
        rescue StandardError => e
          assert false, "Registration request parsing failed: #{e}"
        end
      registered_client_id = JSON.parse(registration_request.response_body)['client_id']

      requests.clear
      load_tagged_requests(TOKEN_TAG, UDAP_TAG)
      skip_if requests.blank?, 'No UDAP token requests made.'

      jti_list = []
      token_list = []
      requests.each_with_index do |token_request, index|
        request_params = URI.decode_www_form(token_request.request_body).to_h
        check_request_params(request_params, index + 1)
        check_client_assertion(request_params['client_assertion'], index + 1, jti_list, registration_token,
                               registered_client_id, token_request.created_at)
        token_list << extract_token_from_response(token_request)
      end

      output udap_tokens: token_list.compact.join("\n")

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid token requests detected. See messages for details.'
    end

    def check_request_params(params, request_num)
      if params['grant_type'] != 'client_credentials'
        add_message('error',
                    "Token request #{request_num} had an incorrect `grant_type`: expected 'client_credentials', " \
                    "but got '#{params['grant_type']}'")
      end
      if params['client_assertion_type'] != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        add_message('error',
                    "Token request #{request_num} had an incorrect `client_assertion_type`: " \
                    "expected 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', " \
                    "but got '#{params['client_assertion_type']}'")
      end
      return unless params['udap'].to_s != '1'

      add_message('error',
                  "Token request #{request_num} had an incorrect `udap`: " \
                  "expected '1', " \
                  "but got '#{params['udap']}'")
    end

    def check_client_assertion(assertion, request_num, jti_list, registration_token, registered_client_id, request_time)
      decoded_token =
        begin
          JWT::EncodedToken.new(assertion)
        rescue StandardError => e
          add_message('error', "Token request #{request_num} contained an invalid client assertion jwt: #{e}")
          nil
        end

      return unless decoded_token.present?

      # header checked with signature
      check_jwt_payload(decoded_token.payload, request_num, jti_list, registered_client_id, request_time)
      check_jwt_signature(decoded_token, registration_token, request_num)
    end

    def check_jwt_payload(claims, request_num, jti_list, registered_client_id, request_time) # rubocop:disable Metrics/CyclomaticComplexity
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
      error = MockUDAPServer.udap_assertion_signature_verification(encoded_token.jwt, registration_token.jwt)

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
