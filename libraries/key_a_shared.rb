# Named this way because it needs to be loaded before our other libraries

module BswTech
  module Gpg
    module SharedKey
      def get_draft_key_from_cookbook(type, cookbook_name, cookbook_file)
        parse_key(type, cookbook_file_contents(cookbook_file, cookbook_name))
      end

      def get_draft_key_from_string(type, key_as_base64_string)
        parse_key(type, key_as_base64_string)
      end

      private

      def parse_key(type, key_contents)
        retriever = GpgRetriever.new
        executor = lambda do |command, input|
          contents = run_command command, :input => input
          gpg_output = contents.stdout
          Chef::Log.debug "Output from GPG #{gpg_output}"
          gpg_output
        end
        result = retriever.get_key_info_from_base64 executor, type, key_contents
        Chef::Log.debug "Parsed key details #{result}"
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