require 'jwt'
require 'faraday'
require 'time'
require_relative '../urls'
require_relative '../tags'
require_relative '../udap_jwt_builder'

module UDAPSecurityTestKit
  module MockUDAPServer
    SUPPORTED_SCOPES = ['openid', 'system/*.read', 'user/*.read', 'patient/*.read'].freeze

    module_function

    def udap_server_metadata(suite_id)
      base_url = "#{Inferno::Application['base_url']}/custom/#{suite_id}"
      response_body = {
        udap_versions_supported: ['1'],
        udap_profiles_supported: ['udap_dcr', 'udap_authn', 'udap_authz'],
        udap_authorization_extensions_supported: ['hl7-b2b'],
        udap_authorization_extensions_required: [],
        udap_certifications_supported: [],
        udap_certifications_required: [],
        grant_types_supported: ['client_credentials'],
        scopes_supported: SUPPORTED_SCOPES,
        token_endpoint: base_url + TOKEN_PATH,
        token_endpoint_auth_methods_supported: ['private_key_jwt'],
        token_endpoint_auth_signing_alg_values_supported: ['RS256', 'RS384', 'ES384'],
        registration_endpoint: base_url + REGISTRATION_PATH,
        registration_endpoint_jwt_signing_alg_values_supported: ['RS256', 'RS384', 'ES384'],
        signed_metadata: udap_signed_metadata_jwt(base_url)
      }.to_json

      [200, { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, [response_body]]
    end

    def make_udap_token_response(request, response, test_session_id)
      assertion = request.params[:client_assertion]
      client_id = client_id_from_client_assertion(assertion)

      software_statement = udap_registration_software_statement(test_session_id)
      signature_error = udap_token_signature_verification(assertion, software_statement)

      if signature_error.present?
        update_response_for_invalid_assertion(response, signature_error)
        return
      end

      exp_min = 60
      response_body = {
        access_token: client_id_to_token(client_id, exp_min),
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

    def udap_signed_metadata_jwt(base_url)
      jwt_claim_hash = {
        iss: base_url + FHIR_PATH,
        sub: base_url + FHIR_PATH,
        exp: 5.minutes.from_now.to_i,
        iat: Time.now.to_i,
        jti: SecureRandom.hex(32),
        token_endpoint: base_url + TOKEN_PATH,
        registration_endpoint: base_url + REGISTRATION_PATH
      }.compact

      UDAPJWTBuilder.encode_jwt_with_x5c_header(
        jwt_claim_hash,
        test_kit_private_key,
        'RS256',
        [test_kit_cert]
      )
    end

    def root_ca_cert
      File.read(
        ENV.fetch('UDAP_ROOT_CA_CERT_FILE',
                  File.join(__dir__, '..',
                            'certs', 'infernoCA.pem'))
      )
    end

    def root_ca_private_key
      File.read(
        ENV.fetch('UDAP_CA_PRIVATE_KEY_FILE',
                  File.join(__dir__, '..',
                            'certs', 'infernoCA.key'))
      )
    end

    def test_kit_cert
      File.read(
        ENV.fetch('UDAP_TEST_KIT_CERT_FILE',
                  File.join(__dir__, '..',
                            'certs', 'TestClient.pem'))
      )
    end

    def test_kit_private_key
      File.read(
        ENV.fetch('UDAP_TEST_KIT_PRIVATE_KEY_FILE',
                  File.join(__dir__, '..',
                            'certs', 'TestClientPrivateKey.key'))
      )
    end

    def parsed_request_body(request)
      JSON.parse(request.request_body)
    rescue JSON::ParserError
      nil
    end

    def parsed_io_body(request)
      parsed_body = begin
        JSON.parse(request.body.read)
      rescue JSON::ParserError
        nil
      end
      request.body.rewind

      parsed_body
    end

    def jwt_claims(encoded_jwt)
      JWT.decode(encoded_jwt, nil, false)[0]
    end

    def client_uri_to_client_id(client_uri)
      Base64.urlsafe_encode64(client_uri, padding: false)
    end

    def client_id_to_client_uri(client_id)
      Base64.urlsafe_decode64(client_id)
    end

    def client_id_to_token(client_id, exp_min)
      token_structure = {
        client_id:,
        expiration: exp_min.minutes.from_now.to_i,
        nonce: SecureRandom.hex(8)
      }.to_json

      Base64.urlsafe_encode64(token_structure, padding: false)
    end

    def decode_token(token)
      JSON.parse(Base64.urlsafe_decode64(token))
    rescue JSON::ParserError
      nil
    end

    def token_to_client_id(token)
      decode_token(token)&.dig('client_id')
    end

    def request_has_expired_token?(request)
      return false if request.params[:session_path].present?

      token = request.headers['authorization']&.delete_prefix('Bearer ')
      decoded_token = decode_token(token)
      return false unless decoded_token&.dig('expiration').present?

      decoded_token['expiration'] < Time.now.to_i
    end

    def update_response_for_expired_token(response)
      response.status = 401
      response.format = :json
      response.body = FHIR::OperationOutcome.new(
        issue: FHIR::OperationOutcome::Issue.new(severity: 'fatal', code: 'expired',
                                                 details: FHIR::CodeableConcept.new(text: 'Bearer token has expired'))
      ).to_json
    end

    def udap_reg_signature_verification(assertion_jwt)
      assertion_body, assertion_header = JWT.decode(assertion_jwt, nil, false)
      return 'missing `x5c` header' if assertion_header['x5c'].blank?

      leaf_cert_der = Base64.decode64(assertion_header['x5c'].first)
      leaf_cert = OpenSSL::X509::Certificate.new(leaf_cert_der)

      signature_error = udap_assertion_signature_verification(assertion_jwt, leaf_cert, assertion_header['alg'])
      return signature_error if signature_error.present?

      # check the certificate's SAN extension for the issuer name
      issuer = assertion_body['iss']
      begin
        alt_names =
          leaf_cert.extensions
            .find { |extension| extension.oid == 'subjectAltName' }.value
      rescue NoMethodError
        return 'Could not find Subject Alternative Name extension in leaf certificate'
      end
      return if alt_names.include?("URI:#{issuer}")

      "`iss` claim `#{issuer}` not found in Subject Alternative Name extension " \
        "from the `x5c` JWT header: `#{alt_names}`"
    end

    def udap_token_signature_verification(assertion_jwt, registration_jwt)
      _assertion_body, assertion_header = JWT.decode(assertion_jwt, nil, false)
      return 'missing `x5c` header' if assertion_header['x5c'].blank?

      leaf_cert_der = Base64.decode64(assertion_header['x5c'].first)
      leaf_cert = OpenSSL::X509::Certificate.new(leaf_cert_der)

      signature_error = udap_assertion_signature_verification(assertion_jwt, leaf_cert, assertion_header['alg'])
      return signature_error if signature_error.present?
      return unless registration_jwt.present?

      # check trust
      _registration_body, registration_header = JWT.decode(registration_jwt, nil, false)
      return if assertion_header['x5c'].first == registration_header['x5c'].first

      'signing cert does not match registration cert'
    end

    def udap_assertion_signature_verification(assertion_jwt, signing_cert, algorithm)
      return 'missing `alg` header' unless algorithm.present?

      signature_validation_result = UDAPSecurityTestKit::UDAPJWTValidator.validate_signature(
        assertion_jwt,
        algorithm,
        signing_cert
      )
      return if signature_validation_result[:success]

      signature_validation_result[:error_message]
    end

    def udap_registration_software_statement(test_session_id)
      registration_requests =
        Inferno::Repositories::Requests.new.tagged_requests(test_session_id, [UDAP_TAG, REGISTRATION_TAG])
      return unless registration_requests.present?

      parsed_body = MockUDAPServer.parsed_request_body(registration_requests.last)
      parsed_body&.dig('software_statement')
    end

    def update_response_for_invalid_assertion(response, error_message)
      response.status = 401
      response.format = :json
      response.body = { error: 'invalid_client', error_description: error_message }.to_json
    end

    def client_id_from_client_assertion(client_assertion_jwt)
      return unless client_assertion_jwt.present?

      jwt_claims(client_assertion_jwt)&.dig('iss')
    end

    def check_jwt_timing(issue_claim, expiration_claim, request_time) # rubocop:disable Metrics/CyclomaticComplexity
      add_message('error', 'Registration software statement `iat` claim is missing') unless issue_claim.present?
      add_message('error', 'Registration software statement `exp` claim is missing') unless expiration_claim.present?
      return unless issue_claim.present? && expiration_claim.present?

      unless issue_claim.is_a?(Numeric)
        add_message('error',
                    "Registration software statement `iat` claim is invalid: expected a number, got '#{issue_claim}'")
      end
      unless expiration_claim.is_a?(Numeric)
        add_message('error',
                    'Registration software statement `exp` claim is invalid: ' \
                    "expected a number, got '#{expiration_claim}'")
      end
      return unless issue_claim.is_a?(Numeric) && expiration_claim.is_a?(Numeric)

      issue_time = Time.at(issue_claim)
      expiration_time = Time.at(expiration_claim)
      unless expiration_time > issue_time
        add_message('error',
                    'Registration software statement `exp` claim is invalid: ' \
                    'cannot be before the `iat` claim.')
      end
      unless expiration_time <= issue_time + 5.minutes
        add_message('error',
                    'Registration software statement `exp` claim is invalid: ' \
                    'cannot be more than 5 minutes after the `iat` claim.')
      end
      unless issue_time <= request_time
        add_message('error',
                    'Registration software statement `iat` claim is invalid: ' \
                    'cannot be after the request time.')
      end
      unless expiration_time > request_time
        add_message('error',
                    'Registration software statement `exp` claim is invalid: ' \
                    'it has expired.')
      end

      nil
    end
  end
end
