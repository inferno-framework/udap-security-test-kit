require_relative '../../lib/udap_security_test_kit/generate_client_certs_test'
require_relative '../../lib/udap_security_test_kit/default_cert_file_loader'

RSpec.describe UDAPSecurityTestKit::GenerateClientCertsTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_generate_client_certs') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }

  let(:udap_client_cert_pem) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:udap_client_private_key_pem) do
    UDAPSecurityTestKit::DefaultCertFileLoader.load_test_client_private_key_file
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

  it 'omits if client cert and private key are input' do
    result = run(runnable, udap_client_cert_pem:,
                           udap_client_private_key_pem:,
                           udap_cert_iss: 'iss')
    expect(result.result).to eq('omit')
  end

  it 'generates valid cert and private key when inputs are empty' do
    result = run(runnable, udap_client_cert_pem: '',
                           udap_client_private_key_pem: '',
                           udap_cert_iss: '')

    expect(result.result).to eq('pass')

    output_json = JSON.parse(result.output_json)
    expect(output_json.first['name']).to eq('udap_cert_iss')
    expect(output_json.second['name']).to eq('udap_client_cert_pem')
    expect(output_json.third['name']).to eq('udap_client_private_key_pem')

    output_json.each do |output|
      expect(output['value'].present?).to be true
    end

    # verify outputs can be loaded into objects correctly
    client_cert = OpenSSL::X509::Certificate.new(output_json.second['value'])
    client_private_key = OpenSSL::PKey.read(output_json.third['value'])

    # Verify private key
    expect(client_cert.check_private_key(client_private_key)).to be true
  end
end
