module BswTech
  module Gpg
    class GpgRetriever
      def initialize
        @parser = BswTech::Gpg::GpgParser.new
        @keyring_specifier = BswTech::Gpg::KeyringSpecifier.new
      end

      # type is :secret_key or :public_key
      def get_current_installed_keys(executor, type, keyring=:default)
        list_param = type == :secret_key ? '--list-secret-keys' : '--list-keys'
        keyring_param = keyring == :default ? ' ' : @keyring_specifier.get_custom_keyring(type, keyring)
        raw_output = executor["gpg2#{keyring_param} #{list_param} --with-fingerprint --with-colons"]
        @parser.parse_output_ring raw_output
      end

      # type is :secret_key or :public_key
      def get_key_info_from_base64(executor, type, base64)
        raw_output = executor['gpg2 --with-fingerprint --with-colons', base64]
        result = @parser.parse_output_external raw_output
        raise "Multiple keys returned from a single base64 import should not happen!  Keys returned: #{result}" if result.length > 1
        single_result = result.first
        unless single_result.type == type
          raise "Key #{single_result} is a #{single_result.type} but you're trying to import a #{type}"
        end
        single_result
      end
    end
  end
end