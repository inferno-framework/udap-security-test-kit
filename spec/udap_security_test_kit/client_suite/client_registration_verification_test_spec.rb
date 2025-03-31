require_relative '../../../lib/udap_security_test_kit/urls'
require_relative '../../../lib/udap_security_test_kit/tags'
require_relative '../../../lib/udap_security_test_kit/udap_jwt_builder'
require_relative '../../../lib/udap_security_test_kit/udap_client_assertion_payload_builder'
require_relative '../../../lib/udap_security_test_kit/endpoints/mock_udap_server'

RSpec.describe UDAPSecurityTestKit::UDAPClientRegistrationVerification do # rubocop:disable RSpec/SpecFilePathFormat
  include UDAPSecurityTestKit::URLs
  let(:suite_id) { 'udap_security_client' }
  let(:test) { described_class }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:dummy_result) { repo_create(:result, test_session_id: test_session.id) }
  let(:udap_client_uri) { 'urn:test' }
  let(:key) { UDAPSecurityTestKit::MockUdapServer.test_kit_private_key }
  let(:cert) { UDAPSecurityTestKit::MockUdapServer.test_kit_cert }
  let(:reg_url) { registration_url }
  let(:reg_claims) do
    {
      iss: udap_client_uri,
      sub: udap_client_uri,
      aud: reg_url,
      exp: 5.minutes.from_now.to_i,
      iat: Time.now.to_i,
      jti: SecureRandom.hex(32),
      client_name: 'Test Client',
      grant_types: ['client_credentials'],
      token_endpoint_auth_method: 'private_key_jwt',
      scope: 'system/*.read',
      contacts: ['mailto:test@inferno.healthit.gov']
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
  let(:reg_claims_bad) do
    {
      iss: udap_client_uri,
      sub: udap_client_uri,
      aud: 'wrong',
      exp: 5.minutes.from_now.to_i,
      iat: Time.now.to_i,
      jti: SecureRandom.hex(32),
      client_name: 'Test Client',
      grant_types: ['client_credentials'],
      token_endpoint_auth_method: 'private_key_jwt',
      scope: 'system/*.read'
    }
  end
  let(:reg_ss_bad) do
    make_signed_udap_jwt(reg_claims_bad, key, [cert])
  end
  let(:reg_request_body_bad) do
    {
      software_statement: reg_ss_bad,
      certifications: [],
      udap: '1'
    }.to_json
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

  it 'omits if not configured for udap' do
    result = run(test)
    expect(result.result).to eq('omit')
  end

  it 'skips if no registration requests' do
    result = run(test, udap_client_uri:)
    expect(result.result).to eq('skip')
  end

  it 'passes if the registration request is valid' do
    create_reg_request(reg_request_body)
    result = run(test, udap_client_uri:)
    expect(result.result).to eq('pass')
  end

  it 'fails if the registration request has the wrong aud' do
    create_reg_request(reg_request_body_bad)
    result = run(test, udap_client_uri:)
    expect(result.result).to eq('fail')
  end
end
