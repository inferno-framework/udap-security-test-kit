require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'

module UDAPSecurityTestKit
  class UDAPClientRegistrationVerification < Inferno::Test
    include URLs

    id :udap_client_registration_verification
    title 'Verify UDAP Registration'
    description %(
        During this test, Inferno will verify that the client's UDAP
        registration request is conformant.
      )
    input :udap_client_uri,
          optional: false

    run do
      omit_if udap_client_uri.blank?, # for re-use: mark the udap_client_uri input as optional when importing to enable
              'Not configured for UDAP authentication.'

      load_tagged_requests(UDAP_TAG, REGISTRATION_TAG)
      skip_if requests.empty?, 'No UDAP Registration Requests made.'

      verified_request = requests.last
      parsed_body = MockUDAPServer.parsed_request_body(verified_request)
      assert parsed_body.present?, 'Registration request body is not valid JSON.'

      check_request_body(parsed_body)
      check_software_statement(parsed_body['software_statement'], verified_request.created_at)

      assert messages.none? { |msg|
        msg[:type] == 'error'
      }, 'Invalid registration request. See messages for details.'
    end

    def check_request_body(request_body)
      if request_body['udap'].blank?
        add_message('error', '`udap` key with a value of `1` missing in the registration request')
      elsif request_body['udap'] != '1'
        add_message('error',
                    'The registration request contained an incorrect `udap` value: expected `1`, ' \
                    "got `#{request_body['udap']}`")
      end

      return unless request_body['certifications'].present?

      request_body['certifications'].each_with_index do |certification_jwt, index|
        JWT.decond(certification_jwt)
      rescue StandardError => e
        add_message('error',
                    "Certification #{index + 1} in the registration request is not a valid signed jwt: #{e}")
      end
    end

    def check_software_statement(software_statement_jwt, request_time)
      unless software_statement_jwt.present?
        add_message('error',
                    'Registration is missing a `software_statement` key')
        return
      end

      claims, _headers = begin
        JWT.decode(software_statement_jwt, nil, false)
      rescue StandardError => e
        add_message('error',
                    "Registration software statement does not follow the jwt structure: #{e}")
        return
      end

      # headers checked with signature
      check_software_statement_claims(claims, request_time)
      check_jwt_signature(software_statement_jwt)
    end

    def check_software_statement_claims(claims, request_time) # rubocop:disable Metrics/CyclomaticComplexity
      unless claims['iss'] == udap_client_uri
        add_message('error',
                    'Registration software statement `iss` claim is incorrect: ' \
                    "expected '#{udap_client_uri}', got '#{claims['iss']}'")
      end
      unless claims['sub'] == udap_client_uri
        add_message('error',
                    'Registration software statement `sub` claim is incorrect: ' \
                    "expected '#{udap_client_uri}', got '#{claims['sub']}'")
      end
      unless claims['aud'] == client_registration_url
        add_message('error',
                    'Registration software statement `aud` claim is incorrect: ' \
                    "expected '#{client_registration_url}', got '#{claims['aud']}'")
      end

      check_software_statement_grant_types(claims)
      MockUDAPServer.check_jwt_timing(claims['iat'], claims['exp'], request_time)

      add_message('error', 'Registration software statement `jti` claim is missing.') unless claims['jti'].present?
      unless claims['client_name'].present?
        add_message('error', 'Registration software statement `client_name` claim is missing.')
      end
      check_software_statement_contacts(claims['contacts'])
      unless claims['token_endpoint_auth_method'] == 'private_key_jwt'
        add_message('error', 'Registration software statement `token_endpoint_auth_method` claim is incorrect: ' \
                             "expected `token_endpoint_auth_method`, got #{claims['token_endpoint_auth_method']}.")
      end
      add_message('error', 'Registration software statement `scope` claim is missing.') unless claims['scope'].present?

      nil
    end

    def check_software_statement_contacts(contacts)
      unless contacts.present?
        add_message('error', 'Registration software statement `contacts` claim is missing.')
        return
      end
      unless contacts.is_a?(Array)
        add_message('error', 'Registration software statement `contacts` claim is missing.')
        return
      end
      unless contacts.find { |contact| valid_uri?(contact, required_scheme: 'mailto') }.present?
        add_message('error', 'Registration software statement `contacts` claim has no ' \
                             'valid `mailto` uri entry.')
      end

      nil
    end

    def check_software_statement_grant_types(claims) # rubocop:disable Metrics/CyclomaticComplexity
      unless claims['grant_types'].present?
        add_message('error', 'Registration software statement `grant_types` claim is missing')
        return
      end

      unless claims['grant_types'].is_a?(Array)
        add_message('error', 'Registration software statement `grant_types` claim must be a list.')
        return
      end

      has_client_credentials = claims['grant_types'].include?('client_credentials')
      has_authorization_code = claims['grant_types'].include?('authorization_code')

      unless has_client_credentials || has_authorization_code
        add_message('error', 'Registration software statement `grant_types` claim must contain one of ' \
                             "'authorization_code' or 'client_credentials'")
        return
      end

      if has_client_credentials && has_authorization_code
        add_message('error', 'Registration software statement `grant_types` claim cannot contain both ' \
                             "'authorization_code' and 'client_credentials'")
      end

      extra_grants = claims['grant_types'].reject do |grant|
        ['client_credentials', 'authorization_code', 'refresh_token'].include?(grant)
      end
      unless extra_grants.blank?
        add_message('error', 'Registration software statement `grant_types` claim cannot contain values beyond ' \
                             "'authorization_code', 'client_credentials', and 'refresh_token")
      end

      check_client_credentials_software_statement(claims) if has_client_credentials
      check_authorization_code_software_statement(claims) if has_authorization_code

      nil
    end

    def check_authorization_code_software_statement(claims) # rubocop:disable Metrics/CyclomaticComplexity
      if claims['redirect_uris'].blank?
        add_message('error', 'Registration software statement `redirect_uris` must be present when' \
                             "the 'authorization_code' `grant_type` is requested.")
      elsif !claims['redirect_uris'].is_a?(Array)
        add_message('error', 'Registration software statement `redirect_uris` must be a list when' \
                             "the 'authorization_code' `grant_type` is requested.")
      else
        claims['redirect_uris'].each do |redirect_uri|
          unless valid_uri?(redirect_uri, required_scheme: 'https')
            add_message('error', "Registration software statement `redirect_uris` entry #{index + 1} is invalid: " \
                                 'it is not a valid https uri.')
          end
        end
      end

      if claims['logo_uri'].blank?
        add_message('error', 'Registration software statement `logo_uri` must be present when' \
                             "the 'authorization_code' `grant_type` is requested.")
      else
        unless valid_uri?(claims['logo_uri'], required_scheme: 'https')
          add_message('error', 'Registration software statement `logo_uri` is invalid: it is not a valid https uri.')
        end
        unless ['gif', 'jpg', 'jpeg', 'png'].include?(claims['logo_uri'].split['.'].last.downcase)
          add_message('error', 'Registration software statement `logo_uri` is invalid: it must point to a ' \
                               'PNG, JPG, or GIF file.')
        end
      end

      if claims['response_types'].blank?
        add_message('error', 'Registration software statement `response_types` must be present when' \
                             "the 'authorization_code' `grant_type` is requested.")
      else
        unless claims['response_types'].is_a?(Array) &&
               claims['response_types'].size == 1 &&
               claims['response_types'][0] == 'code'
          add_message('error', 'Registration software statement `response_types` claim is invalid: ' \
                               "must contain exactly one entry with the value 'code'.")
        end
      end

      nil
    end

    def check_client_credentials_software_statement(claims)
      unless claims['redirect_uris'].nil?
        add_message('error', 'Registration software statement `redirect_uris` must not be present when' \
                             "the 'client_credentials' `grant_type` is requested.")
      end

      unless claims['response_types'].nil?
        add_message('error', 'Registration software statement `response_types` must not be present when' \
                             "the 'client_credentials' `grant_type` is requested.")
      end

      if claims['grant_types'].include?('refresh_token')
        add_message('error', "Registration software statement `response_types` cannot contain 'refresh_token' when" \
                             "the 'client_credentials' `grant_type` is requested.")
      end

      nil
    end

    def check_jwt_signature(jwt)
      error = MockUDAPServer.udap_reg_signature_verification(jwt)

      return unless error.present?

      add_message('error', "Signature validation failed on registration request: #{error}")
    end

    def valid_uri?(url, required_scheme: nil)
      uri = URI.parse(url)
      required_scheme.blank? || uri.scheme == required_scheme
    rescue URI::InvalidURIError
      false
    end
  end
end
