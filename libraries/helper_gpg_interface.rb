module BswTech
  module Gpg
    class GpgInterface
      # Use :default if
      def initialize
        @parser = BswTech::Gpg::GpgParser.new
        @keyring_specifier = BswTech::Gpg::KeyringSpecifier.new
        @command_runner = BswTech::CommandRunner.new
      end

      # type is :secret_key or :public_key
      def get_current_installed_keys(username, type, keyring=:default)
        list_param = type == :secret_key ? '--list-secret-keys' : '--list-keys'
        command = get_gpg_cmd type, keyring
        raw_output = @command_runner.run command="#{command} #{list_param} --with-fingerprint --with-colons",
                                         as_user=username
        @parser.parse_output_ring raw_output
      end

      def get_key_header(base64)
        raw_output = @command_runner.run command='gpg2 --with-fingerprint --with-colons', as_user=:default, input=base64
        result = @parser.parse_output_external raw_output
        raise "Multiple keys returned from a single base64 import should not happen!  Keys returned: #{result}" if result.length > 1
        result.first
      end

      def import_trust(username, base64, keyring=:default)
        key = get_key_header base64
        gpg_command = get_gpg_cmd key.type, keyring
        @command_runner.run command="#{gpg_command} --import-ownertrust",
                            as_user=username,
                            input="#{key.fingerprint}:6:\n"
      end

      def delete_keys(username, key_header_to_delete, keyring=:default)
        type = key_header_to_delete.type
        delete_param = type == :public_key ? '--delete-key' : '--delete-secret-and-public-key'
        gpg_command = get_gpg_cmd type, keyring
        @command_runner.run command="#{gpg_command} #{delete_param} --batch --yes #{key_header_to_delete.fingerprint}",
                            as_user=username
      end

      def import_keys(username, base64, keyring=:default)
        key = get_key_header base64
        gpg_cmd = get_gpg_cmd(key.type, keyring)
        @command_runner.run command="#{gpg_cmd} --import",
                            as_user=username,
                            input=base64
      end

      private

      def get_gpg_cmd(type, keyring)
        keyring_param = get_keyring_param type, keyring
        # When not using the default keyring, gpg2 will complain about not being able to find a public key that we trust
        "gpg2 --no-auto-check-trustdb#{keyring_param}".strip
      end

      def get_keyring_param(type, keyring)
        keyring == :default ? ' ' : @keyring_specifier.get_custom_keyring(type, keyring)
      end

      def get_key_type(key_contents)
        valid = {:public_key => '-----BEGIN PGP PUBLIC KEY BLOCK-----',
                 :secret_key => '-----BEGIN PGP PRIVATE KEY BLOCK-----'}
        occurrences = valid.flat_map do |key_type, pattern|
          regex = Regexp.new pattern, Regexp::MULTILINE
          count = key_contents.scan(regex).length
          {
              key_type => count
          }
        end
        occurrences = Hash[*occurrences.collect { |h| h.to_a }.flatten]
        nothing = occurrences.values.uniq == [0]
        fail "Supplied key contents did NOT start with '-----BEGIN PGP PUBLIC KEY BLOCK-----' or '-----BEGIN PGP PRIVATE KEY BLOCK-----'" if nothing
        dupe = lambda do |type|
          fail "Supplied key contents has #{occurrences[type]} #{type} values, only 1 is allowed" if occurrences[type] > 1
        end
        dupe[:public_key]
        dupe[:secret_key]
        multiple = occurrences.values.count { |c| c >= 1 }
        fail 'Supplied key contents has both secret and public keys, only 1 key is allowed' if multiple > 1
        single = occurrences.find { |type, count| count == 1 }
        type = single[0]
        type
      end
    end
  end
end