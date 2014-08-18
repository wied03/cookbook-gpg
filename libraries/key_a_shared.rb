# Named this way because it needs to be loaded before our other libraries

module BswTech
  module Gpg
    module SharedKey
      def get_draft_key_from_cookbook(cookbook_name, cookbook_file)
        parse_key(cookbook_file_contents(cookbook_file, cookbook_name))
      end

      def get_draft_key_from_string(key_as_base64_string)
        parse_key(key_as_base64_string)
      end

      private

      def get_key_type(key_contents)
        valid = {:public_key => '-----BEGIN PGP PUBLIC KEY BLOCK-----',
                 :secret_key => '-----BEGIN PGP PRIVATE KEY BLOCK-----'}
        occurrences = valid.flat_map do |key_type, pattern|
          regex = Regexp.new pattern, Regexp::MULTILINE
          count = key_contents.scan(regex).length
          {
              key_type => count
          }
        end
        occurrences = Hash[*occurrences.collect { |h| h.to_a }.flatten]
        nothing = occurrences.values.uniq == [0]
        fail "Supplied key contents did NOT start with '-----BEGIN PGP PUBLIC KEY BLOCK-----' or '-----BEGIN PGP PRIVATE KEY BLOCK-----'" if nothing
        dupe = lambda do |type|
          fail "Supplied key contents has #{occurrences[type]} #{type} values, only 1 is allowed" if occurrences[type] > 1
        end
        dupe[:public_key]
        dupe[:secret_key]
        multiple = occurrences.values.count { |c| c >= 1 }
        fail 'Supplied key contents has both secret and public keys, only 1 key is allowed' if multiple > 1
        single = occurrences.find {|type,count| count == 1}
        single[0]
      end

      def parse_key(key_contents)
        retriever = GpgRetriever.new
        executor = lambda do |command, input|
          contents = run_command command, :input => input
          gpg_output = contents.stdout
          Chef::Log.debug "Output from GPG command #{command} is #{gpg_output}"
          gpg_output
        end
        type = get_key_type key_contents
        result = retriever.get_key_info_from_base64 executor, type, key_contents
        Chef::Log.debug "Parsed key details into #{result}"
        result
      end

      def cookbook_file_contents(source, cookbook_name)
        ::File.read(cookbook_file_location(source, cookbook_name))
      end

      def cookbook_file_location(source, cookbook_name)
        cookbook = run_context.cookbook_collection[cookbook_name]
        cookbook.preferred_filename_on_disk_location(node, :files, source)
      end

      def temp_filename(prefix)
        Dir::Tmpname.create([prefix, '.gpg']) {}
      end
    end
  end
end

class Chef
  class Recipe
    # Allow recipes to use fingerprints, etc.
    include BswTech::Gpg::SharedKey

    # Unlike our LWRP, we don't want to run this as a specific user, so use a simpler implementation
    def run_command(*args)
      cmd = Mixlib::ShellOut.new(*args)
      cmd.run_command
      cmd.error!
      cmd
    end
  end
end