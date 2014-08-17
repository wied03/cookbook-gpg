module BswTech
  module Gpg
    class GpgParser
      def parse(gpg_output)
        regex = Regexp.new 'pub\s+\S+/(\S+).*?$\s+Key fingerprint = (.*?)$\s+uid\s+(.*?)$', Regexp::MULTILINE
        gpg_output.scan(regex).map do |match|
          Gpg::KeyDetails.new(match[1], match[2], match[0])
        end
      end
    end
  end
end