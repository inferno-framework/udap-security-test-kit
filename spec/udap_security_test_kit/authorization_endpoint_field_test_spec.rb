require_relative '../../lib/udap_security_test_kit/authorization_endpoint_field_test'

RSpec.describe UDAPSecurityTestKit::AuthorizationEndpointFieldTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_authorization_endpoint_field') }
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

  it 'skips if grant_types_supported field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('skip')
  end

  it 'skips if grant_types_supported values are not an array' do
    config = { grant_types_supported: 'authorization_code' }
    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('skip')
  end

  it 'omits if authorization_code is not a supported grant type' do
    config = { grant_types_supported: ['client_credentials'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('omit')
  end

  it 'fails if authorization_code is a supported grant type but authorization_endpoint field is not present' do
    config = { grant_types_supported: ['authorization_code'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
  end

  it 'fails if authorization_endpoint is not a string' do
    config = { grant_types_supported: ['authorization_code'], authorization_endpoint: ['http://abc'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be a String/)
  end

  it 'fails if authorization_endpoint is a non-uri string' do
    config = { grant_types_supported: ['authorization_code'], authorization_endpoint: 'def' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/valid URI/)
  end

  it 'passes if authorization_code is a supported grant type and authorization_endpoint is a uri string' do
    config = { grant_types_supported: ['authorization_code'], authorization_endpoint: 'http://abc' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end
end
