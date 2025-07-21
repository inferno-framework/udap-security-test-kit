require_relative '../../lib/udap_security_test_kit/registration_success_test'
require_relative '../../lib/udap_security_test_kit/default_cert_file_loader'

RSpec.describe UDAPSecurityTestKit::RegistrationSuccessTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_registration_success') }
  let(:udap_client_cert_pem) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:udap_client_private_key_pem) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_private_key_file
  end

  let(:udap_cert_iss) { 'https://inferno.org/udap_security_test_kit/1716935719' }
  let(:udap_registration_endpoint) { 'http://example.fhir.com/registration' }
  let(:udap_jwt_signing_alg) { 'RS256' }
  let(:udap_registration_requested_scope) { 'system/*' }
  let(:udap_registration_grant_type) { 'client_credentials' }
  let(:udap_registration_certifications) { '' }
  let(:udap_client_registration_status) { 'new' }
  let(:input) do
    {
      udap_client_cert_pem:,
      udap_client_private_key_pem:,
      udap_cert_iss:,
      udap_registration_endpoint:,
      udap_jwt_signing_alg:,
      udap_registration_requested_scope:,
      udap_registration_grant_type:,
      udap_registration_certifications:,
      udap_client_registration_status:
    }
  end

  context 'when new client is being registered' do
    it 'fails if response status is not 201' do
      stub_request(:post, udap_registration_endpoint)
        .to_return(status: 200, body: {}.to_json)

      result = run(runnable, input)

      expect(result.result).to eq('fail')
    end

    it 'passes when response status is 201' do
      stub_request(:post, udap_registration_endpoint)
        .to_return(status: 201, body: {}.to_json)

      result = run(runnable, input)

      expect(result.result).to eq('pass')
    end
  end

  context 'when existing client is updating its registration data' do
    it 'fails if response status is not 200 or 201' do
      stub_request(:post, udap_registration_endpoint)
        .to_return(status: 401, body: {}.to_json)

      input[:udap_client_registration_status] = 'update'
      result = run(runnable, input)

      expect(result.result).to eq('fail')
    end

    it 'passes when response status is 200' do
      stub_request(:post, udap_registration_endpoint)
        .to_return(status: 200, body: {}.to_json)

      input[:udap_client_registration_status] = 'update'
      result = run(runnable, input)

      expect(result.result).to eq('pass')
    end

    it 'passes when response status is 201' do
      stub_request(:post, udap_registration_endpoint)
        .to_return(status: 201, body: {}.to_json)

      input[:udap_client_registration_status] = 'update'
      result = run(runnable, input)

      expect(result.result).to eq('pass')
    end
  end
end
