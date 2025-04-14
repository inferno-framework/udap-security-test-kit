RSpec.describe UDAPSecurityTestKit::MockUDAPServer, :request, :runnable do # rubocop:disable RSpec/SpecFilePathFormat
  let(:suite_id) { 'udap_security_client' }
  let(:test) { suite.children[1].children[0] } # access test
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:dummy_result) { repo_create(:result, test_session_id: test_session.id) }
  let(:token_url) { "/custom/#{suite_id}#{UDAPSecurityTestKit::TOKEN_PATH}" }
  let(:access_url) { "/custom/#{suite_id}/fhir/Patient/999" }
  let(:access_response) { '{"resourceType": "Patent"}' }

  let(:udap_client_id) { 'aHR0cDovL2xvY2FsaG9zdDo0NTY3L2N1c3RvbS9nMzNfdGVzdF9zdWl0ZS9maGly' }
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
  let(:udap_reg_request_valid) do
    File.read(File.join(__dir__, '../..', 'fixtures', 'udap_reg_request_valid.json'))
  end
  let(:udap_assertion_correct_cert) do
    UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
      udap_payload_invalid,
      leaf_key,
      'RS256',
      [leaf_cert]
    )
  end
  let(:udap_assertion_wrong_cert) do
    UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
      udap_payload_invalid,
      root_key,
      'RS256',
      [root_cert]
    )
  end
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

  def make_jwt(payload, header, alg, jwk)
    token = JWT::Token.new(payload:, header:)
    token.sign!(algorithm: alg, key: jwk.signing_key)
    token.jwt
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

  before do
    allow(UDAPSecurityTestKit::UDAPClientOptions).to receive(:oauth_flow)
      .and_return(UDAPSecurityTestKit::CLIENT_CREDENTIALS_TAG)
  end

  describe 'when generating token responses for UDAP' do
    it 'returns 401 when the signature is invalid' do
      create_reg_request(udap_reg_request_valid)
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
      create_reg_request(udap_reg_request_valid)
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
      create_reg_request(udap_reg_request_valid)
      inputs = { client_id: udap_client_id }
      result = run(test, inputs)
      expect(result.result).to eq('wait')

      post_json(token_url, udap_token_request_body_sig_valid)
      expect(last_response.status).to eq(200)

      result = results_repo.find(result.id)
      expect(result.result).to eq('wait')
    end
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
end
