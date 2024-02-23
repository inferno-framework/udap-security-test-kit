require 'jwt'

module UDAPSecurity
  class SignedMetadataFieldTest < Inferno::Test
    include Inferno::DSL::Assertions

    title 'signed_metadata field'
    id :udap_signed_metadata_field
    description %(
       `signed_metadata` is a string containing a JWT listing the server's endpoints
      )

    input :udap_well_known_metadata_json
    output :signed_metadata_jwt

    run do
      assert_valid_json(udap_well_known_metadata_json)
      config = JSON.parse(udap_well_known_metadata_json)

      assert config.key?('signed_metadata'), '`signed_metadata is a required field'
      jwt = config['signed_metadata']

      assert jwt.is_a?(String), "`signed_metadata` should be a String, but found #{jwt.class.name}"
      output signed_metadata_jwt: jwt

      jwt_regex = %r{^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$}

      assert jwt.match?(jwt_regex), '`signed_metadata` is not a valid JWT'
    end
  end
end
