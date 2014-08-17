module BswTech
  module Gpg
    class GpgParser
      # type is :ring or :external
      def parse(type, gpg_output)
        pattern = type == :ring ?
            '(pub|sec)\s+\S+/(?<id>\S+).*?$\s+Key fingerprint = (?<fp>.*?)$\s+uid\s+(?<user>.*?)$' :
            '(pub|sec)\s+\S+/(?<id>\S+) \S+ (?<user>.*?)$\s+Key fingerprint = (?<fp>.*?)$'
        regex = Regexp.new pattern, Regexp::MULTILINE
        results = []
        gpg_output.scan(regex) do
          match = Regexp.last_match
          results << Gpg::KeyDetails.new(fingerprint=match['fp'],
                                         username=match['user'],
                                         id=match['id'])
        end
        results
      end
    end
  end
end