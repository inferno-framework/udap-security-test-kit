RSpec.describe UDAPSecurityTestKit::UDAPClientAppLaunchAuthorizationRequestVerification do # rubocop:disable RSpec/SpecFilePathFormat
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
      iss: udap_client_uri,
      redirect_uris: [redirect_uri]
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

  def make_signed_udap_jwt(jwt_claim_hash, private_key, cert_list)
    UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
      jwt_claim_hash,
      private_key,
      'RS256',
      cert_list
    )
  end

  def create_authorization_request(body, authorization_code)
    headers ||= [
      {
        type: 'response',
        name: 'Location',
        value: "#{redirect_uri}?code=#{authorization_code}"
      }
    ]
    repo_create(
      :request,
      direction: 'incoming',
      url: "#{authorization_url}?#{Rack::Utils.build_query(body)}",
      result: dummy_result,
      test_session_id: test_session.id,
      status: 302,
      headers:,
      verb: 'get',
      tags: [UDAPSecurityTestKit::AUTHORIZATION_TAG, UDAPSecurityTestKit::UDAP_TAG,
             UDAPSecurityTestKit::AUTHORIZATION_CODE_TAG]
    )
  end

  it 'skips if no registration requests for udap' do
    result = run(test, client_id:)
    expect(result.result).to eq('skip')
    expect(result.result_message).to eq("Input 'udap_registration_jwt' is nil, skipping test.")
  end

  it 'skips if no authorization requests' do
    result = run(test, udap_registration_jwt: reg_ss, client_id:)
    expect(result.result).to eq('skip')
    expect(result.result_message).to eq('No UDAP authorization requests made.')
  end

  it 'passes for a valid authorization request' do
    create_authorization_request({ response_type: 'code', client_id:, redirect_uri: }, authorization_code)
    result = run(test, udap_registration_jwt: reg_ss, client_id:)
    expect(result.result).to eq('pass')
  end

  it 'fails for an invalid authorization request' do
    create_authorization_request({ client_id: }, authorization_code)
    result = run(test, udap_registration_jwt: reg_ss, client_id:)
    expect(result.result).to eq('fail')
  end
end
