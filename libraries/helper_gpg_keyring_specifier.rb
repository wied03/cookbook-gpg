module BswTech
  module Gpg
    class KeyringSpecifier
      def get_custom_keyring(type, keyring)
        param = type == :secret_key ? '--secret-keyring' : '--keyring'
        # When not using the default keyring, gpg2 will complain about not being able to find a public key that we trust
        " --no-auto-check-trustdb --no-default-keyring #{param} #{keyring}"
      end
    end
  end
end