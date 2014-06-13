module BswTech
  module Gpg
    module SharedKey
      def with_draft_key_info
        tmp_keyring_pri = temp_filename 'tmp_pri_keyring'
        tmp_keyring_pub = temp_filename 'tmp_pub_keyring'
        begin
          Chef::Log.info 'Setting up temporary keyring'
          run_command "gpg2 --import --no-default-keyring --secret-keyring #{tmp_keyring_pri} --keyring #{tmp_keyring_pub}",
                      :input => @new_resource.key_contents
          draft = get_draft_key_details tmp_keyring_pub
          yield draft
        ensure
          run_command "shred -n 20 -z -u #{tmp_keyring_pri}"
          FileUtils.rm_rf tmp_keyring_pub
          # GPG also leaves this file laying around
          FileUtils.rm_rf "#{tmp_keyring_pub}~"
        end
      end

      def temp_filename(prefix)
        Dir::Tmpname.create([prefix, '.gpg']) {}
      end

      def get_draft_key_details(public_keyring_path)
        Chef::Log.info 'Fetching fingerprints and user names of draft keys'
        contents = run_command "gpg2 --list-keys --fingerprint --no-default-keyring --keyring #{public_keyring_path}"
        parser = BswTech::Gpg::GpgParser.new(contents.stdout)
        parser.keys[0]
      end
    end
  end
end