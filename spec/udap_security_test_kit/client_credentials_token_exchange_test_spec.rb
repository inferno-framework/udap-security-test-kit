require_relative '../../lib/udap_security_test_kit/client_credentials_token_exchange_test'
require_relative '../../lib/udap_security_test_kit/default_cert_file_loader'

RSpec.describe UDAPSecurityTestKit::ClientCredentialsTokenExchangeTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_client_credentials_token_exchange') }
  let(:udap_client_credentials_flow_client_cert_pem) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:udap_client_credentials_flow_client_private_key) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_private_key_file
  end

  let(:base_url) { 'http://example.com/fhir' }
  let(:udap_token_endpoint) { 'http://example.com/token' }

  let(:input) do
    {
      udap_token_endpoint:,
      udap_client_id: 'CLIENT_ID',
      udap_client_credentials_flow_client_cert_pem:,
      udap_client_credentials_flow_client_private_key:,
      udap_jwt_signing_alg: 'RS256'
    }
  end

  it 'passes if the token response has a 200 status' do
    stub_request(:post, udap_token_endpoint)
      .to_return(status: 200, body: {}.to_json)

    result = run(runnable, input)
    expect(result.result).to eq('pass')
  end
end
