require 'mixlib/shellout'
require 'tempfile'

class Chef
  class Provider
    class BswGpgKeyManage < Chef::Provider
      def initialize(new_resource, run_context)
        super
        # The way shellout works, the home directory is not set for the user and gpg needs that, easiest way is to use the shell
        @home_dir = run_command("/bin/sh -c \"echo -n ~#{@new_resource.for_user}\"").stdout
      end

      def whyrun_supported?
        true
      end

      def load_current_resource
        @current_resource ||= Chef::Resource::BswGpgKeyManage.new(new_resource.name)
        @current_resource.key_contents(new_resource.key_contents)
        @current_resource.for_user(new_resource.for_user)
        @current_resource
      end

      def run_command(*args)
        args << {} unless args.last.is_a? Hash
        options = args.last
        options[:user] = @new_resource.for_user
        options[:env] = {'HOME' => @home_dir} if @home_dir
        cmd = Mixlib::ShellOut.new(*args)
        cmd.run_command
        cmd.error!
        cmd
      end

      def get_draft_key_details(public_keyring_path)
        Chef::Log.info 'Fetching fingerprints and user names of draft keys'
        contents = run_command "gpg2 --list-keys --fingerprint --no-default-keyring --keyring #{public_keyring_path}"
        parser = BswTech::Gpg::GpgParser.new(contents.stdout)
        parser.keys[0]
      end

      def get_current_key_details()
        Chef::Log.info 'Checking currently installed keys'
        contents = run_command 'gpg2 --list-keys --fingerprint'
        parser = BswTech::Gpg::GpgParser.new(contents.stdout)
        parser.keys
      end

      def key_needs_to_be_installed(draft, current)
        Chef::Log.info 'Checking if any keys are installed'
        current.all? { |x| x.fingerprint != draft.fingerprint }
      end

      def remove_existing_keys(draft, current)
        key_to_delete = current.find { |x| x.username == draft.username }
        if key_to_delete
          Chef::Log.info "Deleting existing key for #{key_to_delete.username} in order to replace it"
          run_command "gpg2 --delete-secret-and-public-key --batch --yes #{key_to_delete.fingerprint_no_whitespace}"
        end
      end

      def temp_filename(prefix)
        Dir::Tmpname.create([prefix, '.gpg']) {}
      end

      def trust_key(key)
        run_command 'gpg2 --import-ownertrust', :input => "#{key.fingerprint_no_whitespace}:6:\n"
      end

      def action_replace
        tmp_keyring_pri = temp_filename 'tmp_pri_keyring'
        tmp_keyring_pub = temp_filename 'tmp_pub_keyring'
        begin
          Chef::Log.info 'Setting up temporary keyring to compare keys'
          run_command "gpg2 --import --no-default-keyring --secret-keyring #{tmp_keyring_pri} --keyring #{tmp_keyring_pub}",
                      :input => @new_resource.key_contents
          draft = get_draft_key_details tmp_keyring_pub
          current = get_current_key_details
          if key_needs_to_be_installed draft, current
            converge_by "Importing key #{draft.username} into keyring" do
              remove_existing_keys draft, current
              run_command 'gpg2 --import',
                          :input => @new_resource.key_contents
              trust_key draft
            end
          end
        ensure
          run_command "shred -n 20 -z -u #{tmp_keyring_pri}"
          FileUtils.rm_rf tmp_keyring_pub
          # GPG also leaves this file laying around
          FileUtils.rm_rf "#{tmp_keyring_pub}~"
        end
      end
    end
  end
end