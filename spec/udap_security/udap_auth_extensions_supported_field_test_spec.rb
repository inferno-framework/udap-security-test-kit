require_relative '../../lib/udap_security/udap_auth_extensions_supported_field_test'

RSpec.describe UDAPSecurity::UDAPAuthExtensionsSupportedFieldTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_auth_extensions_supported_field') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }
  let(:required_flow_type) { [''] }

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

  context 'when the server can support any authorization flow(s)' do
    it 'fails if field is not present' do
      config = {}

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('fail')
    end

    it 'fails if udap_authorization_extensions_supported value is not an array' do
      config = { udap_authorization_extensions_supported: 'hl7-b2b' }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('fail')
    end

    it 'passes if array is empty' do
      config = { udap_authorization_extensions_supported: [] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('pass')
    end

    it 'passes if array includes a string' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json,
                             required_flow_type:)

      expect(result.result).to eq('pass')
    end
  end

  context 'when the server must support client_credentials flow' do
    it 'fails if hl7-b2b extension is not supported' do
      config = { udap_authorization_extensions_supported: [] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: ['client_credentials'])

      expect(result.result).to eq('fail')
    end

    it 'passes if hl7-b2b extension is supported' do
      config = { udap_authorization_extensions_supported: ['hl7-b2b'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json, required_flow_type: ['client_credentials'])

      expect(result.result).to eq('pass')
    end
  end
end
