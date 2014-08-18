module BswTech
  module Gpg
    class GpgRetriever
      def initialize
        @parser = BswTech::Gpg::GpgParser.new
      end

      # type is :secret_key or :public_key
      def get_current_installed_keys(executor, type)
        list_param = type == :secret_key ? '--list-secret-keys' : '--list-keys'
        raw_output = executor["gpg2 #{list_param} --with-fingerprint --with-colons"]
        @parser.parse_output_ring raw_output
      end

      # type is :secret_key or :public_key
      def get_key_info_from_base64(executor, type, base64)
        raw_output = executor['gpg2 --with-fingerprint --with-colons', base64]
        @parser.parse_output_external raw_output
      end
    end
  end
end