# Named this way because it needs to be loaded before our other libraries

module BswTech
  module Gpg
    module SharedKey
      def with_draft_key_info(options)
        public_key_contents = options.include?(:public_key_contents) ?
            options[:public_key_contents] :
            cookbook_file_contents(options[:cookbook_file],options[:cookbook])
        tmp_keyring_pri = temp_filename 'tmp_pri_keyring'
        tmp_keyring_pub = temp_filename 'tmp_pub_keyring'
        begin
          Chef::Log.info 'Setting up temporary keyring'
          run_command "gpg2 --import --no-default-keyring --secret-keyring #{tmp_keyring_pri} --keyring #{tmp_keyring_pub}",
                      :input => public_key_contents
          draft = parse_details_from_keyring tmp_keyring_pub
          yield draft
        ensure
          run_command "shred -n 20 -z -u #{tmp_keyring_pri}"
          FileUtils.rm_rf tmp_keyring_pub
          # GPG also leaves this file laying around
          FileUtils.rm_rf "#{tmp_keyring_pub}~"
        end
      end

      private

      def cookbook_file_contents(source, cookbook_name)
        ::File.read(cookbook_file_location(source,cookbook_name))
      end

      def cookbook_file_location(source, cookbook_name)
        cookbook = run_context.cookbook_collection[cookbook_name]
        cookbook.preferred_filename_on_disk_location(node, :files, source)
      end

      def temp_filename(prefix)
        Dir::Tmpname.create([prefix, '.gpg']) {}
      end

      def parse_details_from_keyring(public_keyring_path)
        Chef::Log.info 'Fetching fingerprints and user names of draft keys'
        contents = run_command "gpg2 --list-keys --fingerprint --no-default-keyring --keyring #{public_keyring_path}"
        parser = BswTech::Gpg::GpgParser.new(contents.stdout)
        parser.keys[0]
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