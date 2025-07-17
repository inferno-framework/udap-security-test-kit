require_relative '../../lib/udap_security_test_kit/registration_failure_invalid_jwt_signature_test'
require_relative '../../lib/udap_security_test_kit/default_cert_file_loader'

RSpec.describe UDAPSecurityTestKit::RegistrationFailureInvalidJWTSignatureTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_registration_failure_invalid_jwt_signature') }
  let(:udap_client_cert_pem) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:udap_cert_iss) { 'https://inferno.org/udap_security_test_kit/1716935719' }
  let(:udap_registration_endpoint) { 'http://example.fhir.com/registration' }
  let(:udap_jwt_signing_alg) { 'RS256' }
  let(:udap_registration_requested_scope) { 'system/*' }
  let(:udap_registration_grant_type) { 'client_credentials' }
  let(:udap_registration_certifications) { '' }
  let(:udap_auth_code_flow_client_registration_status) { 'update' }
  let(:udap_auth_code_flow_client_cert_pem) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:udap_auth_code_flow_client_private_key) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_private_key_file
  end

  let(:input) do
    {
      udap_client_cert_pem:,
      udap_cert_iss:,
      udap_registration_endpoint:,
      udap_jwt_signing_alg:,
      udap_registration_requested_scope:,
      udap_registration_grant_type:,
      udap_registration_certifications:,
      udap_auth_code_flow_client_registration_status:,
      udap_auth_code_flow_client_private_key:
    }
  end

  it 'fails if response status is not 400' do
    stub_request(:post, udap_registration_endpoint)
      .to_return(status: 200, body: {}.to_json)

    result = run(runnable, input)

    expect(result.result).to eq('fail'), result.result_message
  end

  it 'passes when response status is 400' do
    stub_request(:post, udap_registration_endpoint)
      .to_return(status: 400, body: {}.to_json)

    result = run(runnable, input)

    expect(result.result).to eq('pass'), result.result_message
  end
end
