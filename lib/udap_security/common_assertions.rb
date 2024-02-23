# Module for assertion methods that are used across multiple tests
module CommonAssertions
  extend Inferno::DSL::Assertions

  def self.assert_array_of_strings(config, field)
    values = config[field]

    assert values.is_a?(Array), "`#{field}` should be an Array, but found #{values.class.name}"

    non_string_values = values.reject { |value| value.is_a?(String) }

    assert non_string_values.blank?,
           "`#{field}` should be an Array of strings, but found
            #{non_string_values.map(&:class).map(&:name).join(', ')}"
  end
end
