module BswTech
  module Gpg
    class GpgParser
      @@record_type_mapping = {'pub' => :public_key,
                               'sec' => :secret_key,
                               'fpr' => :fingerprint,
                               'uid' => :user_id}

      def parse_output_ring(gpg_output)
        parse ring_or_external=:ring,
              gpg_output=gpg_output
      end

      def parse_output_external(gpg_output)
        parse ring_or_external=:external,
              gpg_output=gpg_output
      end

      private

      def get_key_type(match)
        @@key_type_mapping[match['keytype']]
      end

      # ID is commonly last 4 bytes or 8 hex characters
      def parse_key_id(full_key_id)
        full_key_id[-8..-1]
      end

      def parse_user_id(raw)
        # colons are used as delimiters
        raw.gsub '\\x3a', ':'
      end

      def parse_record(ring_or_external, record_raw)
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
            result[:id] = parse_key_id fields[4]
          when :user_id
            result[:id] = parse_user_id fields[9]
          when :public_key
            result[:id] = parse_key_id fields[4]
          else
            raise "Should not get to this point, no case statement for record #{fields}"
        end
        if ring_or_external == :external and [:secret_key, :public_key].include?(result[:type]) and fields.length == 10
          result[:uid] = parse_user_id fields[9]
        end
        result
      end

      def get_key_header_from_records(records)
        fingerprint = records.find { |r| r[:type] == :fingerprint }
        raise "Unable to find fingerprint in records #{records}" unless fingerprint
        first_key = records.find { |r| [:public_key, :secret_key].include?(r[:type]) }
        raise "Unable to find public or secret key in records #{records}" unless first_key
        # When looking at an external key, username can be in the same record as the key ID
        username_records = records.select { |r| r[:type] == :user_id }
        if first_key.include? :uid
          username_records << {:id => first_key[:uid]}
        end
        raise "Unable to find username in records #{records}" unless username_records.any?
        usernames = username_records.map { |r| r[:id] }
        user_single_mult = usernames.length == 1 ? usernames[0] : usernames
        Gpg::KeyHeader.new(fingerprint=fingerprint[:contents],
                           usernames=user_single_mult,
                           id=first_key[:id],
                           type=first_key[:type])
      end

      def parse(ring_or_external, gpg_output)
        records = gpg_output.split("\n").map { |raw| parse_record ring_or_external, raw }.compact
        results = []
        records_for_current_key = []
        for record in records
          if [:public_key, :secret_key].include?(record[:type]) && records_for_current_key.any?
            results << get_key_header_from_records(records_for_current_key)
            records_for_current_key.clear
          end
          records_for_current_key << record
        end
        if records_for_current_key.any?
          results << get_key_header_from_records(records_for_current_key)
        end
        results
      end
    end
  end
end