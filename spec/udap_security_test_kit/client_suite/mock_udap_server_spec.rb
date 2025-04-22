RSpec.describe UDAPSecurityTestKit::MockUDAPServer, :request, :runnable do # rubocop:disable RSpec/SpecFilePathFormat
  include UDAPSecurityTestKit::URLs
  let(:suite_id) { 'udap_security_client' }
  let(:test) { suite.children[2].children[0] } # access test
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:dummy_result) { repo_create(:result, test_session_id: test_session.id) }
  let(:reg_url) { client_registration_url }
  let(:authorization_url) { client_authorization_url }
  let(:token_url) { client_token_url }
  let(:access_url) { "/custom/#{suite_id}/fhir/Patient/999" }
  let(:redirect_uri) { 'http://inferno.healthit.gov/redirect' }
  let(:access_response) { '{"resourceType": "Patent"}' }
  let(:udap_client_uri) { 'http://localhost:4567/custom/g33_test_suite/fhir' }
  let(:udap_client_id) { described_class.client_uri_to_client_id(udap_client_uri) }
  let(:udap_payload_invalid) do
    {
      iss: udap_client_id,
      sub: 'different',
      aud: 'http://localhost:4567/custom/davinci_pas_client_suite_v201/auth/token',
      exp: 60.minutes.from_now.to_i,
      iat: Time.now.to_i,
      jti: '96a86a90d27090e8ab3835403fb64fec973977a63d7af5e7cf99064d6bb32092',
      extensions: '{"hl7-b2b":{"version":"1","subject_name":"UDAP Test Kit","organization_name":"Inferno Framework","organization_id":"https://inferno-framework.github.io/","purpose_of_use":["SYSDEV"]}}' # rubocop:disable Layout/LineLength
    }
  end
  let(:root_cert) do
    File.read(File.join(__dir__, '..', '..', '..', 'lib', 'udap_security_test_kit', 'certs', 'InfernoCA.pem'))
  end
  let(:root_key) do
    File.read(File.join(__dir__, '..', '..', '..', 'lib', 'udap_security_test_kit', 'certs', 'InfernoCA.key'))
  end
  let(:leaf_cert) do
    File.read(File.join(__dir__, '..', '..', '..', 'lib', 'udap_security_test_kit', 'certs', 'TestClient.pem'))
  end
  let(:leaf_key) do
    File.read(File.join(__dir__, '..', '..', '..', 'lib', 'udap_security_test_kit', 'certs',
                        'TestClientPrivateKey.key'))
  end
  let(:udap_cc_reg_request_valid) do
    File.read(File.join(__dir__, '../..', 'fixtures', 'udap_cc_reg_request_valid.json'))
  end
  let(:udap_assertion_correct_cert) { make_signed_udap_jwt(udap_payload_invalid, leaf_key, [leaf_cert]) }
  let(:udap_assertion_wrong_cert) { make_signed_udap_jwt(udap_payload_invalid, root_key, [root_cert]) }
  let(:udap_token_request_body_sig_invalid) do
    { grant_type: 'client_credentials',
      client_assertion_type: 'invalid',
      client_assertion: "#{udap_assertion_correct_cert}bad",
      udap: 1 }
  end
  let(:udap_token_request_body_sig_valid) do
    { grant_type: 'client_credentials',
      client_assertion_type: 'invalid',
      client_assertion: udap_assertion_correct_cert,
      udap: 1 }
  end
  let(:udap_token_request_body_wrong_cert) do
    { grant_type: 'client_credentials',
      client_assertion_type: 'invalid',
      client_assertion: udap_assertion_wrong_cert,
      udap: 1 }
  end
  let(:udap_ac_token_request_body_bad_code) do
    { grant_type: 'authorization_code',
      client_assertion_type: 'invalid',
      client_assertion: udap_assertion_wrong_cert,
      udap: 1,
      code: 'invalid' }
  end

  let(:authorization_code) { described_class.client_id_to_token(udap_client_id, 5) }
  let(:udap_ac_token_request_body_valid) do
    { grant_type: 'authorization_code',
      client_assertion_type: 'invalid',
      client_assertion: udap_assertion_correct_cert,
      udap: 1,
      code: authorization_code }
  end
  let(:udap_ac_token_request_body_sig_invalid) do
    { grant_type: 'authorization_code',
      client_assertion_type: 'invalid',
      client_assertion: "#{udap_assertion_correct_cert}bad",
      udap: 1,
      code: authorization_code }
  end
  let(:refresh_token) { described_class.authorization_code_to_refresh_token(authorization_code) }
  let(:udap_refresh_token_request_body_sig_valid) do
    { grant_type: 'refresh_token',
      refresh_token:,
      client_assertion_type: 'invalid',
      client_assertion: udap_assertion_correct_cert,
      udap: 1 }
  end
  let(:udap_refresh_token_request_body_sig_invalid) do
    { grant_type: 'refresh_token',
      refresh_token:,
      client_assertion_type: 'invalid',
      client_assertion: "#{udap_assertion_correct_cert}bad",
      udap: 1 }
  end

  let(:reg_claims) do
    {
      iss: udap_client_uri,
      sub: udap_client_uri,
      aud: reg_url,
      exp: 5.minutes.from_now.to_i,
      iat: Time.now.to_i,
      jti: SecureRandom.hex(32),
      client_name: 'Test Client',
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'private_key_jwt',
      scope: 'system/*.read offline_access openid fhirUser',
      contacts: ['mailto:test@inferno.healthit.gov'],
      logo_uri: 'https://myapp.example.com/MyApp.png',
      redirect_uris: [redirect_uri],
      response_types: ['code']
    }
  end
  let(:reg_ss) do
    make_signed_udap_jwt(reg_claims, leaf_key, [leaf_cert])
  end
  let(:reg_request_body) do
    {
      software_statement: reg_ss,
      certifications: [],
      udap: '1'
    }.to_json
  end

  def make_jwt(payload, header, alg, jwk)
    token = JWT::Token.new(payload:, header:)
    token.sign!(algorithm: alg, key: jwk.signing_key)
    token.jwt
  end

  def make_signed_udap_jwt(jwt_claim_hash, private_key, cert_list)
    UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
      jwt_claim_hash,
      private_key,
      'RS256',
      cert_list
    )
  end

  def create_reg_request(body)
    repo_create(
      :request,
      direction: 'incoming',
      url: 'test',
      result: dummy_result,
      test_session_id: test_session.id,
      request_body: body,
      status: 200,
      tags: [UDAPSecurityTestKit::REGISTRATION_TAG, UDAPSecurityTestKit::UDAP_TAG]
    )
  end

  describe 'when responding to access requests' do
    it 'returns 401 when the access token has expired' do
      expired_token = Base64.strict_encode64({
        client_id: udap_client_id,
        expiration: 1,
        nonce: SecureRandom.hex(8)
      }.to_json)

      inputs = { client_id: udap_client_id, echoed_fhir_response: access_response }
      result = run(test, inputs)
      expect(result.result).to eq('wait')

      header('Authorization', "Bearer #{expired_token}")
      get(access_url)
      expect(last_response.status).to eq(401)

      result = results_repo.find(result.id)
      expect(result.result).to eq('wait')
    end

    it 'returns 200 when the access token has not expired' do
      exp_timestamp = Time.now.to_i

      unexpired_token = Base64.strict_encode64({
        client_id: udap_client_id,
        expiration: exp_timestamp,
        nonce: SecureRandom.hex(8)
      }.to_json)

      allow(Time).to receive(:now).and_return(Time.at(exp_timestamp - 10))

      inputs = { client_id: udap_client_id, echoed_fhir_response: access_response }
      result = run(test, inputs)
      expect(result.result).to eq('wait')

      header('Authorization', "Bearer #{unexpired_token}")
      get(access_url)
      expect(last_response.status).to eq(200)

      result = results_repo.find(result.id)
      expect(result.result).to eq('wait')
    end

    it 'returns 200 when the decoded access token has no expiration' do
      token_no_exp = Base64.strict_encode64({
        client_id: udap_client_id,
        nonce: SecureRandom.hex(8)
      }.to_json)

      inputs = { client_id: udap_client_id, echoed_fhir_response: access_response }
      result = run(test, inputs)
      expect(result.result).to eq('wait')

      header('Authorization', "Bearer #{token_no_exp}")
      get(access_url)
      expect(last_response.status).to eq(200)

      result = results_repo.find(result.id)
      expect(result.result).to eq('wait')
    end
  end

  describe 'for the client_credentials flow' do
    describe 'when generating token responses for UDAP' do
      it 'returns 401 when the signature is invalid' do
        create_reg_request(udap_cc_reg_request_valid)
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_token_request_body_sig_invalid)
        expect(last_response.status).to eq(401)
        expect(last_response.body).to match(/Signature verification failed/)

        result = results_repo.find(result.id)
        expect(result.result).to eq('wait')
      end

      it 'returns 401 when the signature used a cert that was not registered' do
        create_reg_request(udap_cc_reg_request_valid)
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_token_request_body_wrong_cert)
        expect(last_response.status).to eq(401)
        expect(last_response.body).to match(/signing cert does not match registration cert/)

        result = results_repo.find(result.id)
        expect(result.result).to eq('wait')
      end

      it 'returns 200 when no prior registration' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_token_request_body_sig_valid)
        expect(last_response.status).to eq(200)

        result = results_repo.find(result.id)
        expect(result.result).to eq('wait')
      end

      it 'returns 200 when signature valid even if other issues' do
        create_reg_request(udap_cc_reg_request_valid)
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_token_request_body_sig_valid)
        expect(last_response.status).to eq(200)

        result = results_repo.find(result.id)
        expect(result.result).to eq('wait')
      end
    end
  end

  describe 'for the authorization_code flow' do
    describe 'when generating authorization code responses for UDAP' do
      it 'succeeds for conformant request' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        body = URI.encode_www_form([['response_type', 'code'],
                                    ['client_id', udap_client_id],
                                    ['redirect_uri', redirect_uri]])
        post authorization_url, body, 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'
        expect(last_response.status).to eq(302)
        decoded_client_id_from_code = described_class.issued_token_to_client_id(
          Rack::Utils.parse_query(URI.parse(last_response.headers['Location']).query)['code']
        )
        expect(decoded_client_id_from_code).to eq(udap_client_id)
      end

      it 'succeeds for non-conformant request but with client_id and redirect_uri' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        body_missing_response_type = URI.encode_www_form([['client_id', udap_client_id],
                                                          ['redirect_uri', redirect_uri]])
        post authorization_url, body_missing_response_type, 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to_not be_nil
      end

      it 'returns 500 when no client id' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        body_missing_client_id = URI.encode_www_form([['response_type', 'code'],
                                                      ['redirect_uri', redirect_uri]])
        post authorization_url, body_missing_client_id, 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'
        expect(last_response.status).to eq(500)
      end

      it 'returns 401 when no redirect_uri and no registered default' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        body_no_redirect_uri = URI.encode_www_form([['response_type', 'code'],
                                                    ['client_id', udap_client_id]])
        post authorization_url, body_no_redirect_uri, 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'
        expect(last_response.status).to eq(400)
      end
    end

    describe 'when generating token responses for UDAP' do
      it 'returns 500 when a bad code is provided' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_ac_token_request_body_bad_code)
        expect(last_response.status).to eq(500)
      end

      it 'returns 401 when a bad signature is provided' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_ac_token_request_body_sig_invalid)
        expect(last_response.status).to eq(401)
      end

      it 'includes tester-provided context when specified' do
        launch_context = { patient: '123' }.to_json
        inputs = { client_id: udap_client_id, launch_context: }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_ac_token_request_body_valid)
        expect(last_response.status).to eq(200)
        response_body = JSON.parse(last_response.body)
        expect(response_body['patient']).to eq('123')
      end

      it 'includes a refresh token when requested as a part of the scopes' do
        create_reg_request(reg_request_body)
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_ac_token_request_body_valid)
        expect(last_response.status).to eq(200)
        response_body = JSON.parse(last_response.body)
        refresh_token = response_body['refresh_token']
        expect(described_class.refresh_token_to_authorization_code(refresh_token)).to eq(authorization_code)
      end

      it 'provides a id_token when requested through scopes' do
        create_reg_request(reg_request_body)
        fhir_user_relative_reference = 'Patient/123'
        inputs = { client_id: udap_client_id, fhir_user_relative_reference: }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_ac_token_request_body_valid)
        expect(last_response.status).to eq(200)
        response_body = JSON.parse(last_response.body)
        expect(response_body['id_token']).to_not be_nil
        token_body, _token_header = JWT.decode(response_body['id_token'], nil, false)
        expect(token_body['aud']).to eq(udap_client_id)
        expect(token_body['fhirUser']).to eq("#{client_fhir_base_url}/#{fhir_user_relative_reference}")
      end
    end

    describe 'when generating refresh token responses for UDAP' do
      it 'succeeds when request is valid' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        # authorization code request
        body = URI.encode_www_form([['response_type', 'code'],
                                    ['client_id', udap_client_id],
                                    ['redirect_uri', redirect_uri]])
        post authorization_url, body, 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'
        expect(last_response.status).to eq(302)
        auth_code = Rack::Utils.parse_query(URI.parse(last_response.headers['Location']).query)['code']
        udap_refresh_token_request_body_sig_valid['refresh_token'] =
          described_class.authorization_code_to_refresh_token(auth_code)

        post_json(token_url, udap_refresh_token_request_body_sig_valid)
        expect(last_response.status).to eq(200)
      end

      it 'returns 401 when no corresponding authorization request' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_refresh_token_request_body_sig_valid)
        expect(last_response.status).to eq(401)
      end

      it 'returns 401 when the client assertion is invalid' do
        inputs = { client_id: udap_client_id }
        result = run(test, inputs)
        expect(result.result).to eq('wait')

        post_json(token_url, udap_refresh_token_request_body_sig_invalid)
        expect(last_response.status).to eq(401)
      end
    end
  end
end
