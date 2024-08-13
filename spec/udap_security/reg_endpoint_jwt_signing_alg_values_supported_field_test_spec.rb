require_relative '../../lib/udap_security/reg_endpoint_jwt_signing_alg_values_supported_field_test'

RSpec.describe UDAPSecurityTestKit::RegEndpointJWTSigningAlgValuesSupportedFieldTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_reg_endpoint_jwt_signing_alg_values_supported_field') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }

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

  it 'omits if field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('omit')
  end

  it 'passes if registration_endpoint_jwt_signing_alg_values_supported is an array of uri strings' do
    config = { registration_endpoint_jwt_signing_alg_values_supported: ['http://abc', 'http://def'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end

  it 'fails if registration_endpoint_jwt_signing_alg_values_supported is not an array' do
    config = { registration_endpoint_jwt_signing_alg_values_supported: 'http://abc' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be an Array/)
  end

  it 'fails if registration_endpoint_jwt_signing_alg_values_supported is an array with a non-string element' do
    config = { registration_endpoint_jwt_signing_alg_values_supported: ['http://abc', 1] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Array of strings/)
  end
end
