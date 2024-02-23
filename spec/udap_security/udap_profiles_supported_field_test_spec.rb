require_relative '../../lib/udap_security/udap_profiles_supported_field_test'

RSpec.describe UDAPSecurity::UDAPProfilesSupportedFieldTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_profiles_supported_field') }
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

  it 'fails if field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
  end

  it 'passes if udap_profiles_supported is an array of two or more strings containing "udap_dcr" and "udap_authn"' do
    config = { udap_profiles_supported: ['udap_dcr', 'udap_authn'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end

  it 'fails if udap_profiles_supported is not an array' do
    config = { udap_profiles_supported: 'udap_dcr' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be an Array/)
  end

  it 'fails if udap_profiles_supported is an array with a non-string element' do
    config = { udap_profiles_supported: ['udap_dcr', 1] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Array of strings/)
  end

  context 'when client_credentials grant type is included in grant_types_supported' do
    it 'fails if udap_profiles_supported does not include "udap_authz"' do
      config = { grant_types_supported: ['client_credentials'], udap_profiles_supported: ['udap_dcr', 'udap_authn'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json)

      expect(result.result).to eq('fail')
    end

    it 'passes if udap_profiles_supported includes "udap_authz"' do
      config = { grant_types_supported: ['client_credentials'],
                 udap_profiles_supported: ['udap_dcr', 'udap_authn', 'udap_authz'] }

      result = run(runnable, udap_well_known_metadata_json: config.to_json)

      expect(result.result).to eq('pass')
    end
  end
end
