module BswTech
  module Gpg
    class KeyringSpecifier
      def get_custom_keyring(type, keyring)
        param = type == :secret_key ? '--secret-keyring' : '--keyring'
        " --no-default-keyring #{param} #{keyring}"
      end
    end
  end
end