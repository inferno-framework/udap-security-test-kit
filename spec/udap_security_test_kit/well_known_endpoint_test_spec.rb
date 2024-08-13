require_relative '../../lib/udap_security_test_kit/well_known_endpoint_test'

RSpec.describe UDAPSecurityTestKit::WellKnownEndpointTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_well_known_endpoint') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }
  let(:udap_fhir_base_url) { 'http://example.com/fhir' }

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

  it 'passes if JSON is served from the UDAP well-known endpoint' do
    stub_request(:get, "#{udap_fhir_base_url}/.well-known/udap")
      .to_return(status: 200, body: {}.to_json)

    result = run(runnable, udap_fhir_base_url:)

    expect(result.result).to eq('pass')
  end

  it 'fails if a 200 is not received' do
    stub_request(:get, "#{udap_fhir_base_url}/.well-known/udap")
      .to_return(status: 201, body: {}.to_json)

    result = run(runnable, udap_fhir_base_url:)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/200/)
  end

  it 'fails if it receives invalid JSON' do
    stub_request(:get, "#{udap_fhir_base_url}/.well-known/udap")
      .to_return(status: 200, body: '[[')

    result = run(runnable, udap_fhir_base_url:)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Invalid JSON/)
  end
end
