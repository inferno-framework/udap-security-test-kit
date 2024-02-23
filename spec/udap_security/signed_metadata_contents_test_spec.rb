require_relative '../../lib/udap_security/signed_metadata_contents_test'

RSpec.describe UDAPSecurity::SignedMetadataContentsTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_signed_metadata_contents') }
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

  it 'skips if signed_metadata_jwt is blank' do
    config = {}
    udap_fhir_base_url = 'http://example.fhir.com'

    result = run(runnable, udap_well_known_metadata_json: config.to_json, signed_metadata_jwt: nil, udap_fhir_base_url:)
    expect(result.result).to eq('skip')
  end

  # TODO: - test remainder of test conditions
end
