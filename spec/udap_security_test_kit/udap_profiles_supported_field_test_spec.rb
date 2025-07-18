require_relative '../../lib/udap_security_test_kit/udap_profiles_supported_field_test'

RSpec.describe UDAPSecurityTestKit::UDAPProfilesSupportedFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_profiles_supported_field') }

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
