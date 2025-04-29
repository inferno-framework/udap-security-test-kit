RSpec.describe UDAPSecurityTestKit::UDAPClientTokenRequestAuthorizationCodeVerification do # rubocop:disable RSpec/SpecFilePathFormat
  include UDAPSecurityTestKit::URLs
  let(:suite_id) { 'udap_security_client' }
  let(:test) { described_class }
  let(:test_session) do # overriden to add suite options
    repo_create(
      :test_session,
      suite: suite_id,
      suite_options: [Inferno::DSL::SuiteOption.new(
        id: :client_type,
        value: UDAPSecurityTestKit::UDAPClientOptions::UDAP_AUTHORIZATION_CODE
      )]
    )
  end
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:dummy_result) { repo_create(:result, test_session_id: test_session.id) }
  let(:udap_client_uri) { 'http://localhost:4567/custom/g33_test_suite/fhir' }
  let(:udap_client_id) { UDAPSecurityTestKit::MockUDAPServer.client_uri_to_client_id(udap_client_uri) }
  let(:client_id) { UDAPSecurityTestKit::MockUDAPServer.client_uri_to_client_id(udap_client_uri) }
  let(:key) { UDAPSecurityTestKit::MockUDAPServer.test_kit_private_key }
  let(:cert) { UDAPSecurityTestKit::MockUDAPServer.test_kit_cert }
  let(:token_url) { "#{Inferno::Application['base_url']}/custom/udap_security_client/auth/token" }
  let(:authorization_url) { client_authorization_url }
  let(:authorization_code) { UDAPSecurityTestKit::MockUDAPServer.client_id_to_token(udap_client_id, 5) }
  let(:redirect_uri) { 'http://inferno.healthit.gov/redirect' }
  let(:access_token) { 'xyz' }
  let(:reg_claims) do
    {
      iss: udap_client_uri
    }
  end
  let(:reg_ss) do
    make_signed_udap_jwt(reg_claims, key, [cert])
  end
  let(:reg_request_body) do
    {
      software_statement: reg_ss,
      certifications: [],
      udap: '1'
    }.to_json
  end
  let(:reg_response_body) do
    {
      client_id:,
      software_statement: reg_ss
    }.to_json
  end
  let(:b2b_extension) do
    {
      version: '1',
      organization_id: '12345',
      purpose_of_use: 'treatment'
    }
  end
  let(:client_assertion_body_valid) do
    UDAPSecurityTestKit::UDAPClientAssertionPayloadBuilder.build(client_id, token_url, { 'hl7-b2b' => b2b_extension })
  end
  let(:client_assertion_valid) { make_signed_udap_jwt(client_assertion_body_valid, key, [cert]) }
  let(:another_client_assertion_body_valid) do
    UDAPSecurityTestKit::UDAPClientAssertionPayloadBuilder.build(client_id, token_url, { 'hl7-b2b' => b2b_extension })
  end
  let(:another_client_assertion_valid) { make_signed_udap_jwt(another_client_assertion_body_valid, key, [cert]) }
  let(:token_request_hash_valid) do
    {
      grant_type: 'authorization_code',
      code: authorization_code,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: client_assertion_valid,
      udap: '1'
    }
  end

  let(:token_request_hash_invalid) do
    {
      grant_type: 'authorization_code',
      code: authorization_code,
      client_assertion_type: 'invalid',
      client_assertion: client_assertion_valid,
      udap: '1'
    }
  end

  let(:token_refresh_request_hash_valid) do
    {
      grant_type: 'refresh_token',
      refresh_token: UDAPSecurityTestKit::MockUDAPServer.authorization_code_to_refresh_token(authorization_code),
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: another_client_assertion_valid,
      udap: '1'
    }
  end

  let(:token_refresh_request_hash_invalid) do
    {
      grant_type: 'refresh_token',
      refresh_token: UDAPSecurityTestKit::MockUDAPServer.authorization_code_to_refresh_token(authorization_code),
      client_assertion_type: 'invalid',
      client_assertion: another_client_assertion_valid,
      udap: '1'
    }
  end

  def make_signed_udap_jwt(jwt_claim_hash, private_key, cert_list)
    UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
      jwt_claim_hash,
      private_key,
      'RS256',
      cert_list
    )
  end

  def create_authorization_request(code)
    headers ||= [
      {
        type: 'response',
        name: 'Location',
        value: "#{redirect_uri}?code=#{code}"
      }
    ]
    repo_create(
      :request,
      direction: 'incoming',
      url: "#{authorization_url}?client_id=#{client_id}",
      result: dummy_result,
      test_session_id: test_session.id,
      status: 302,
      headers:,
      tags: [UDAPSecurityTestKit::AUTHORIZATION_TAG, UDAPSecurityTestKit::UDAP_TAG,
             UDAPSecurityTestKit::AUTHORIZATION_CODE_TAG]
    )
  end

  def create_token_request(request_body)
    repo_create(
      :request,
      direction: 'incoming',
      url: token_url,
      result: dummy_result,
      test_session_id: test_session.id,
      request_body: URI.encode_www_form(request_body),
      response_body: { access_token: }.to_json,
      status: 200,
      tags: [UDAPSecurityTestKit::TOKEN_TAG, UDAPSecurityTestKit::UDAP_TAG, UDAPSecurityTestKit::AUTHORIZATION_CODE_TAG]
    )
  end

  def create_refresh_token_request(request_body)
    repo_create(
      :request,
      direction: 'incoming',
      url: token_url,
      result: dummy_result,
      test_session_id: test_session.id,
      request_body: URI.encode_www_form(request_body),
      response_body: { access_token: }.to_json,
      status: 200,
      tags: [UDAPSecurityTestKit::TOKEN_TAG, UDAPSecurityTestKit::UDAP_TAG, UDAPSecurityTestKit::REFRESH_TOKEN_TAG]
    )
  end

  it 'skips if no registration requests for udap' do
    result = run(test, client_id:)
    expect(result.result).to eq('skip')
    expect(result.result_message).to eq("Input 'udap_registration_jwt' is nil, skipping test.")
  end

  it 'skips if no token requests' do
    result = run(test, udap_registration_jwt: reg_ss, client_id:)
    expect(result.result).to eq('skip')
    expect(result.result_message).to eq('No UDAP token requests made.')
  end

  it 'passes for a valid request' do
    create_authorization_request(authorization_code)
    create_token_request(token_request_hash_valid)
    result = run(test, udap_registration_jwt: reg_ss, client_id:)
    expect(result.result).to eq('pass')
    output_tokens = JSON.parse(result.output_json).find { |output| output['name'] == 'udap_tokens' }&.dig('value')
    expect(output_tokens).to eq(access_token)
  end

  it 'fails for an invalid client assertion type' do
    create_authorization_request(authorization_code)
    create_token_request(token_request_hash_invalid)
    result = run(test, udap_registration_jwt: reg_ss, client_id:)
    expect(result.result).to eq('fail')
  end

  it 'skips when only refresh token requests' do
    create_refresh_token_request(token_refresh_request_hash_valid)
    result = run(test, udap_registration_jwt: reg_ss, client_id:)
    expect(result.result).to eq('skip')
    expect(result.result_message).to eq('No UDAP token requests made.')
  end

  it 'passes for a valid refresh token request' do
    create_authorization_request(authorization_code)
    create_token_request(token_request_hash_valid)
    create_refresh_token_request(token_refresh_request_hash_valid)
    result = run(test, udap_registration_jwt: reg_ss, client_id:)
    expect(result.result).to eq('pass')
  end

  it 'passes for an invalid refresh token request' do
    create_authorization_request(authorization_code)
    create_token_request(token_request_hash_valid)
    create_refresh_token_request(token_refresh_request_hash_invalid)
    result = run(test, udap_registration_jwt: reg_ss, client_id:)
    expect(result.result).to eq('fail')
  end
end
