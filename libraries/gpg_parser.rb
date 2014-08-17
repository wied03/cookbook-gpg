module BswTech
  module Gpg
    class GpgParser
      @@key_type_mapping = {'pub' => :public, 'sec' => :secret}

      def parse_output_ring(gpg_output)
        parse pattern='(?<keytype>pub|sec)\s+\S+/(?<id>\S+).*?$\s+Key fingerprint = (?<fp>.*?)$\s+uid\s+(?<user>.*?)$',
              gpg_output=gpg_output
      end

      def parse_output_external(gpg_output)
        parse pattern='(?<keytype>pub|sec)\s+\S+/(?<id>\S+) \S+ (?<user>.*?)$\s+Key fingerprint = (?<fp>.*?)$',
              gpg_output=gpg_output
      end

      private

      def get_key_type(match)
        @@key_type_mapping[match['keytype']]
      end

      def parse(pattern, gpg_output)
        regex = Regexp.new pattern, Regexp::MULTILINE
        results = []
        gpg_output.scan(regex) do
          match = Regexp.last_match
          results << Gpg::KeyDetails.new(fingerprint=match['fp'],
                                         username=match['user'],
                                         id=match['id'],
                                         type=get_key_type(match))
        end
        results
      end
    end
  end
end