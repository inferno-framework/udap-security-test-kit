RSpec.describe UDAPSecurityTestKit::UDAPClientRegistrationAuthorizationCodeVerification do # rubocop:disable RSpec/SpecFilePathFormat
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
  let(:udap_client_uri) { 'urn:test' }
  let(:key) { UDAPSecurityTestKit::MockUDAPServer.test_kit_private_key }
  let(:cert) { UDAPSecurityTestKit::MockUDAPServer.test_kit_cert }
  let(:reg_url) { client_registration_url }
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
      scope: 'system/*.read',
      contacts: ['mailto:test@inferno.healthit.gov'],
      logo_uri: 'https://myapp.example.com/MyApp.png',
      redirect_uris: ['https://myapp.example.com/redirect'],
      response_types: ['code']
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

  it 'skips if no registration requests' do
    result = run(test, udap_client_uri:)
    expect(result.result).to eq('skip')
  end

  it 'passes if the registration request is valid' do
    allow_any_instance_of(OpenSSL::X509::Extension).to receive(:value).and_return("URI:#{udap_client_uri}")
    create_reg_request(reg_request_body)
    result = run(test, udap_client_uri:)
    expect(result.result).to eq('pass')
  end

  it 'fails if the certification SAN doesn\' match the issuer' do
    allow_any_instance_of(OpenSSL::X509::Extension).to receive(:value).and_return('URI:not_the_client_uri')
    create_reg_request(reg_request_body)
    result = run(test, udap_client_uri:)
    expect(result.result).to eq('fail')
  end

  it 'fails if the registration request has the wrong aud' do
    create_reg_request(reg_request_body_bad)
    result = run(test, udap_client_uri:)
    expect(result.result).to eq('fail')
  end
end
