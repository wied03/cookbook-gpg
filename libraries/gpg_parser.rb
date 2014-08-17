module BswTech
  module Gpg
    class GpgParser
      @@record_type_mapping = {'pub' => :public_key,
                               'sec' => :secret_key,
                               'fpr' => :fingerprint}

      def parse_output_ring(gpg_output)
        parse pattern='^(?<keytype>\w+)\s+\S+/(?<id>\S+).*?$\s+Key fingerprint = (?<fp>.*?)$\s+uid\s+(?<user>.*?)$',
              gpg_output=gpg_output
      end

      def parse_output_external(gpg_output)
        parse pattern='^(?<keytype>\w+)\s+\S+/(?<id>\S+) \S+ (?<user>.*?)$\s+Key fingerprint = (?<fp>.*?)$',
              gpg_output=gpg_output
      end

      private

      def get_key_type(match)
        @@key_type_mapping[match['keytype']]
      end

      def parse_record(record_raw)
        fields = record_raw.split ':'
        raw_type = fields[0]
        return nil unless @@record_type_mapping.include? raw_type
        result = {
            :type => @@record_type_mapping[raw_type]
        }
        case result[:type]
          when :fingerprint
            result[:contents] = fields[9]
          when :secret_key
            result[:id] = fields[4]
          else
            raise "Should not get to this point"
        end
      end

      def parse(pattern, gpg_output)
        records = gpg_output.split("\n").map { |raw| parse_record raw }.compact
        results = []
        fingerprint = records.find { |r| r[:type] == :fingerprint }[:contents]
        first_key = records.find { |r| [:public_key, :secret_key].include?(r[:type]) }
        username = records.find { |r| r[:type] == :userid }[:id]
        results << Gpg::KeyDetails.new(fingerprint=fingerprint,
                                       username=username,
                                       id=first_key[:id],
                                       type=first_key[:type])
        results
      end
    end
  end
end