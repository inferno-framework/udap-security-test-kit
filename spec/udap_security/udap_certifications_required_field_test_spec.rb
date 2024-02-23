require_relative '../../lib/udap_security/udap_certifications_required_field_test'

RSpec.describe UDAPSecurity::UDAPCertificationsRequiredFieldTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_certifications_required_field') }
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

  it 'skips if udap_certifications_supported field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('skip')
  end

  it 'omits if no UDAP certifications are supported' do
    config = { udap_certifications_supported: [] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('omit')
  end

  it 'passes if udap_certifications_required is an array of uri strings' do
    config = { udap_certifications_supported: ['http://abc', 'http://def'],
               udap_certifications_required: ['http://abc', 'http://def'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end

  it 'fails if udap_certifications_required is not an array' do
    config = { udap_certifications_supported: ['http://abc', 'http://def'], udap_certifications_required: 'http://abc' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be an Array/)
  end

  it 'fails if udap_certifications_required is an array with a non-string element' do
    config = { udap_certifications_supported: ['http://abc', 'http://def'], udap_certifications_required: ['http://abc', 1] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Array of strings/)
  end

  it 'fails if udap_certifications_required is an array with a non-uri string element' do
    config = { udap_certifications_supported: ['http://abc', 'http://def'], udap_certifications_required: ['http://abc', 'def'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Array of URI strings/)
  end
end
