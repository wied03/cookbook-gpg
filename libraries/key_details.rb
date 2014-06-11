module BswTech
  module Gpg
    class KeyDetails
      attr_accessor :fingerprint
      attr_accessor :username

      def initialize(fingerprint, username)
        @fingerprint = fingerprint
        @username = username
      end
    end
  end
end