require_relative '../../lib/udap_security/authorization_code_token_exchange_test'
require_relative '../../lib/udap_security/udap_request_builder'
require_relative '../../lib/udap_security/default_cert_file_loader'

RSpec.describe UDAPSecurityTestKit::AuthorizationCodeTokenExchangeTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_authorization_code_token_exchange') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }
  let(:udap_client_cert_pem_auth_code_flow) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:udap_client_private_key_auth_code_flow) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_private_key_file
  end

  let(:base_url) { 'http://example.com/fhir' }
  let(:udap_token_endpoint) { 'http://example.com/token' }

  let(:input) do
    {
      udap_authorization_code: 'CODE',
      udap_token_endpoint:,
      udap_client_id: 'CLIENT_ID',
      udap_client_cert_pem_auth_code_flow:,
      udap_client_private_key_auth_code_flow:,
      udap_jwt_signing_alg: 'RS256'
    }
  end

  def create_redirect_request(url)
    repo_create(
      :request,
      direction: 'incoming',
      name: 'redirect',
      url:,
      test_session_id: test_session.id
    )
  end

  def run(runnable, inputs = {})
    test_run_params = { test_session_id: test_session.id }.merge(runnable.reference_hash)
    test_run = Inferno::Repositories::TestRuns.new.create(test_run_params)
    inputs.each do |name, value|
      session_data_repo.save(
        test_session_id: test_session.id,
        name:,
        value:,
        type: runnable.config.input_type(name)
      )
    end
    Inferno::TestRunner.new(test_session:, test_run:).run(runnable)
  end

  it 'passes if the token response has a 200 status' do
    create_redirect_request('http://example.com/redirect?code=CODE')

    stub_request(:post, udap_token_endpoint)
      .to_return(status: 200, body: {}.to_json)

    result = run(runnable, input)
    expect(result.result).to eq('pass')
  end
end
