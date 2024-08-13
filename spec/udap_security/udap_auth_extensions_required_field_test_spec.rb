require_relative '../../lib/udap_security/udap_auth_extensions_required_field_test'

RSpec.describe UDAPSecurityTestKit::UDAPAuthExtensionsRequiredFieldTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_auth_extensions_required_field') }
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

  it 'skips if udap_authorization_extensions_supported field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('skip')
  end

  it 'omits if udap_authorization_extensions_supported field is present but empty' do
    config = { udap_authorization_extensions_supported: [] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('omit')
  end

  context 'when udap_authorization_extensions_supported is present and not empty' do
    it 'fails if udap_authorization_extensions_required field is missing' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json)

      expect(result.result).to eq('fail')
    end

    it 'passes if udap_authorization_extensions_required field is an empty array' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'], udap_authorization_extensions_required: [] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json)

      expect(result.result).to eq('pass')
    end

    it 'passes if array includes a string' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'],
                 udap_authorization_extensions_required: ['hl7-b2b'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json)

      expect(result.result).to eq('pass')
    end
  end
end
