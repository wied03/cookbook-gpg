module BswTech
  module Gpg
    class KeyDetails
      attr_accessor :fingerprint
      attr_accessor :username

      def initialize(fingerprint, username)
        @fingerprint = fingerprint
        @username = username
      end

      def fingerprint_no_whitespace
        fingerprint.gsub ' ', ''
      end
    end
  end
end