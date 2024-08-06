require_relative '../../lib/udap_security/signed_metadata_contents_test'
require_relative '../../lib/udap_security/udap_jwt_builder'
require_relative '../../lib/udap_security/default_cert_file_loader'

RSpec.describe UDAPSecurity::SignedMetadataContentsTest do
  let(:runnable) { Inferno::Repositories::Tests.new.find('udap_signed_metadata_contents') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }
  let(:udap_well_known_metadata) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => ['udap_dcr', 'udap_authn', 'udap_authz'],
      'udap_authorization_extensions_supported' => ['hl7-b2b'],
      'udap_authorization_extensions_required' => [],
      'udap_certifications_supported' => [],
      'udap_certifications_required' => [],
      'grant_types_supported' => ['authorization_code', 'client_credentials', 'refresh_token'],
      'authorization_endpoint' => 'https://inferno.com/udap_security/authz',
      'token_endpoint' => 'https://inferno.com/udap_security/token',
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => 'https://inferno.com/udap_security/registration',
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => signed_metadata_jwt
    }
  end

  let(:signed_metadata_jwt) do
    UDAPSecurity::UDAPJWTBuilder.encode_jwt_with_x5c_header(
      signed_metadata_jwt_payload,
      client_private_key,
      signing_algorithm,
      [client_cert_pem, root_ca]
    ).to_s
  end

  let(:signed_metadata_jwt_payload) do
    {
      'iss' => 'https://inferno.com/udap_security/ac',
      'sub' => 'https://inferno.com/udap_security/ac',
      'exp' => 60.minutes.from_now.to_i,
      'jti' => SecureRandom.hex(32),
      'iat' => Time.now.to_i,
      'authorization_endpoint' => 'https://inferno.com/udap_security/authz',
      'token_endpoint' => 'https://inferno.com/udap_security/token',
      'registration_endpoint' => 'https://inferno.com/udap_security/registration'
    }
  end

  let(:client_cert_pem) do
    UDAPSecurity::DefaultCertFileLoader.load_test_client_cert_pem_file
  end

  let(:client_private_key) do
    UDAPSecurity::DefaultCertFileLoader.load_test_client_private_key_file
  end

  let(:root_ca) do
    UDAPSecurity::DefaultCertFileLoader.load_default_ca_pem_file
  end

  let(:signing_algorithm) { 'RS256' }

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

    result = run(runnable, udap_well_known_metadata_json: config.to_json, signed_metadata_jwt: nil,
                           udap_fhir_base_url:)
    expect(result.result).to eq('skip')
  end

  it 'passes with valid JWT' do
    udap_fhir_base_url = 'https://inferno.com/udap_security/ac'
    json_string = udap_well_known_metadata.to_json
    result = run(
      runnable,
      udap_well_known_metadata_json: json_string,
      signed_metadata_jwt:,
      udap_fhir_base_url:
    )
    expect(result.result).to eq('pass')
  end
end
