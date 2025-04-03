require_relative '../../../lib/udap_security_test_kit/tags'
require_relative '../../../lib/udap_security_test_kit/udap_jwt_builder'
require_relative '../../../lib/udap_security_test_kit/udap_client_assertion_payload_builder'
require_relative '../../../lib/udap_security_test_kit/endpoints/mock_udap_server'

RSpec.describe UDAPSecurityTestKit::UDAPClientTokenRequestVerification do # rubocop:disable RSpec/SpecFilePathFormat
  let(:suite_id) { 'udap_security_client' }
  let(:test) { described_class }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:dummy_result) { repo_create(:result, test_session_id: test_session.id) }
  let(:udap_client_uri) { 'urn:test' }
  let(:client_id) { UDAPSecurityTestKit::MockUDAPServer.client_uri_to_client_id(udap_client_uri) }
  let(:key) { UDAPSecurityTestKit::MockUDAPServer.test_kit_private_key }
  let(:cert) { UDAPSecurityTestKit::MockUDAPServer.test_kit_cert }
  let(:token_url) { 'https://inferno.healthit.gov/suites/custom/udap_security_client/auth/token' }
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
      client_id: client_id,
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
  let(:token_request_hash_valid) do
    {
      grant_type: 'client_credentials',
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: client_assertion_valid,
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

  def create_reg_request(request_body, response_body)
    repo_create(
      :request,
      direction: 'incoming',
      url: 'test',
      result: dummy_result,
      test_session_id: test_session.id,
      request_body:,
      response_body:,
      status: 200,
      tags: [UDAPSecurityTestKit::REGISTRATION_TAG, UDAPSecurityTestKit::UDAP_TAG]
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
      tags: [UDAPSecurityTestKit::TOKEN_TAG, UDAPSecurityTestKit::UDAP_TAG]
    )
  end

  it 'omits if no registration requests for udap' do
    result = run(test)
    expect(result.result).to eq('omit')
    udap_demonstrated_output = JSON.parse(result.output_json).find do |output|
      output['name'] == 'udap_demonstrated'
    end&.dig('value')
    expect(udap_demonstrated_output).to eq('No')
  end

  it 'skips if no token requests' do
    create_reg_request(reg_request_body, reg_response_body)
    result = run(test)
    expect(result.result).to eq('skip')
    udap_demonstrated_output = JSON.parse(result.output_json).find do |output|
      output['name'] == 'udap_demonstrated'
    end&.dig('value')
    expect(udap_demonstrated_output).to eq('Yes')
  end

  it 'passes for a valid request' do
    create_reg_request(reg_request_body, reg_response_body)
    create_token_request(token_request_hash_valid)
    result = run(test)
    expect(result.result).to eq('pass')
    udap_demonstrated_output = JSON.parse(result.output_json).find do |output|
      output['name'] == 'udap_demonstrated'
    end&.dig('value')
    expect(udap_demonstrated_output).to eq('Yes')
    output_tokens = JSON.parse(result.output_json).find { |output| output['name'] == 'udap_tokens' }&.dig('value')
    expect(output_tokens).to eq(access_token)
  end
end
