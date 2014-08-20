module BswTech
  module Gpg
    class KeyHeader
      attr_accessor :fingerprint
      attr_accessor :username
      attr_accessor :id
      attr_accessor :type

      def initialize(fingerprint, username, id, type)
        @fingerprint = fingerprint
        @username = username
        @id = id
        @type = type
      end
    end
  end
end