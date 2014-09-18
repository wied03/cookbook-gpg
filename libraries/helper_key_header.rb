module BswTech
  module Gpg
    class KeyHeader
      attr_accessor :fingerprint
      attr_accessor :usernames
      attr_accessor :id
      attr_accessor :type

      def initialize(fingerprint, usernames, id, type)
        @fingerprint = fingerprint
        @usernames = usernames
        @id = id
        @type = type
      end
    end
  end
end