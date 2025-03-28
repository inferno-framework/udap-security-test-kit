require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'

module UDAPSecurityTestKit
  class UDAPClientTokenRequest < Inferno::Test
    include URLs

    id :udap_client_token_request
    title 'Verify UDAP Token Requests'
    description %(
        Check that UDAP token requests are conformant.
      )

    run do
      load_tagged_requests(REGISTRATION_TAG, UDAP_TAG)
      omit_if requests.blank?, 'UDAP Authentication not demonstrated as a part of this test session.'
      registration_request = requests.last
      registration_assertion = MockUdapServer.parsed_request_body(registration_request)['software_statement']
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
      requests.each_with_index do |token_request, index|
        request_params = URI.decode_www_form(token_request.request_body).to_h
        check_request_params(request_params, index + 1)
        check_client_assertion(request_params['client_assertion'], index + 1, jti_list, registration_token,
                               token_request.url, registered_client_id)
      end

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid token requests detected. See messages for details.'
    end

    def check_request_params(params, index)
      if params['grant_type'] != 'client_credentials'
        add_message('error',
                    "Token request #{index} had an incorrect `grant_type`: expected 'client_credentials', " \
                    "but got '#{params['grant_type']}'")
      end
      if params['client_assertion_type'] != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        add_message('error',
                    "Token request #{index} had an incorrect `client_assertion_type`: " \
                    "expected 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', " \
                    "but got '#{params['client_assertion_type']}'")
      end
      return unless params['udap'].to_s != '1'

      add_message('error',
                  "Token request #{index} had an incorrect `udap`: " \
                  "expected '1', " \
                  "but got '#{params['udap']}'")
    end

    def check_client_assertion(assertion, index, jti_list, registration_token, endpoint_aud, registered_client_id)
      decoded_token =
        begin
          JWT::EncodedToken.new(assertion)
        rescue StandardError => e
          add_message('error', "Token request #{index} contained an invalid client assertion jwt: #{e}")
          nil
        end

      return unless decoded_token.present?

      # header checked with signature
      check_jwt_payload(decoded_token.payload, index, jti_list, endpoint_aud, registered_client_id)
      check_jwt_signature(decoded_token, registration_token, index)
    end

    def check_jwt_payload(claims, index, jti_list, endpoint_aud, registered_client_id)
      if claims['iss'] != registered_client_id
        add_message('error', "client assertion jwt on token request #{index} has an incorrect `iss` claim: " \
                             "expected '#{registered_client_id}', got '#{claims['iss']}'")
      end

      if claims['sub'] != registered_client_id
        add_message('error', "client assertion jwt on token request #{index} has an incorrect `sub` claim: " \
                             "expected '#{registered_client_id}', got '#{claims['sub']}'")
      end

      if claims['aud'] != endpoint_aud
        add_message('error', "client assertion jwt on token request #{index} has an incorrect `aud` claim: " \
                             "expected '#{endpoint_aud}', got '#{claims['aud']}'")
      end

      if claims['exp'].blank?
        add_message('error', "client assertion jwt on token request #{index} is missing the `exp` claim.")
      end

      if claims['jti'].blank?
        add_message('error', "client assertion jwt on token request #{index} is missing the `jti` claim.")
      elsif jti_list.include?(claims['jti'])
        add_message('error', "client assertion jwt on token request #{index} has a `jti` claim that was " \
                             "previouly used: '#{claims['jti']}'.")
      else
        jti_list << claims['jti']
      end

      check_b2b_auth_extension(claims.dig('extensions', 'hl7-b2b'), index)
    end

    def check_b2b_auth_extension(b2b_auth, index)
      if b2b_auth.blank?
        add_message('error', "client assertion jwt on token request #{index} missing the `hl7-b2b` extension.")
        return
      end

      if b2b_auth['version'].blank?
        add_message('error', "the `hl7-b2b` extension on client assertion jwt on token request #{index} is missing " \
                             'the required `version` key.')
      elsif b2b_auth['version'].to_s != '1'
        add_message('error', "the `hl7-b2b` extension on client assertion jwt on token request #{index} has an " \
                             "incorrect `version` value: expected `1`, got #{b2b_auth['version']}.")
      end

      if b2b_auth['organization_id'].blank?
        add_message('error', "the `hl7-b2b` extension on client assertion jwt on token request #{index} is missing " \
                             'the required `organization_id` key.')
      end

      if b2b_auth['purpose_of_use'].blank?
        add_message('error', "the `hl7-b2b` extension on client assertion jwt on token request #{index} is missing " \
                             'the required `purpose_of_use` key.')
      end

      nil
    end

    def check_jwt_signature(encoded_token, registration_token, index)
      error = MockUdapServer.udap_assertion_signature_verification(encoded_token.jwt, registration_token.jwt)

      return unless error.present?

      add_message('error', "Signature validation failed on token request #{index}: #{error}")
    end
  end
end
