module BswTech
  module Gpg
    class GpgParser
      attr_accessor :keys

      def initialize(gpg_output)
        fingerprints = []
        gpg_output.scan(/Key fingerprint = (.*)$/) do |match|
          fingerprints << match[0]
        end
        names = []
        gpg_output.scan(/uid\s+(.*)$/) do |match|
          names << match[0]
        end
        raise "Fingerprints/usernames do not match!" if fingerprints.length != names.length
        @keys = []
        fingerprints.each_index do |i|
          @keys << Gpg::KeyDetails.new(fingerprints[i], names[i])
        end
      end
    end
  end
end