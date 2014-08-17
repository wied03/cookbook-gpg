module BswTech
  module Gpg
    class KeyDetails
      attr_accessor :fingerprint
      attr_accessor :username
      attr_accessor :id

      def initialize(fingerprint, username, id)
        @fingerprint = fingerprint
        @username = username
        @id = id
      end

      def fingerprint_no_whitespace
        fingerprint.gsub ' ', ''
      end
    end
  end
end