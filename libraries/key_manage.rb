require 'mixlib/shellout'
require 'tempfile'

class Chef
  class Provider
    class BswGpgKeyManage < Chef::Provider
      def initialize(new_resource, run_context)
        super
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
        cmd = Mixlib::ShellOut.new(*args)
        cmd.run_command
        cmd.error!
        cmd
      end

      def get_draft_key_details(public_keyring_path)
        Chef::Log.info 'Fetching fingerprints and user names of draft keys'
        contents = run_command("gpg2 --list-keys --fingerprint --no-default-keyring --keyring #{public_keyring_path}", :user => @new_resource.for_user)
        parser = BswTech::Gpg::GpgParser.new(contents.stdout)
        parser.keys[0]
      end

      def get_current_key_details()
        Chef::Log.info 'Checking currently installed keys'
        contents = run_command('gpg2 --list-keys --fingerprint', :user => @new_resource.for_user)
        parser = BswTech::Gpg::GpgParser.new(contents.stdout)
        parser.keys
      end

      def key_needs_to_be_installed(draft, current)
        Chef::Log.info 'Checking if any keys are installed'
        current.all? {|x| x.fingerprint != draft.fingerprint}
      end

      def remove_existing_keys(draft,current)
        key_to_delete = current.find {|x| x.username == draft.username}
        if key_to_delete
          Chef::Log.info "Deleting existing key for #{key_to_delete.username} in order to replace it"
          no_whitespace = key_to_delete.fingerprint.gsub ' ',''
          run_command "gpg2 --delete-secret-and-public-key --batch --yes #{no_whitespace}",
                      :user => @new_resource.for_user
        end
      end

      def temp_filename(prefix)
        Dir::Tmpname.create([prefix, '.gpg']) { }
      end

      def action_replace
        tmp_keyring_pri = temp_filename 'tmp_pri_keyring'
        tmp_keyring_pub = temp_filename 'tmp_pub_keyring'
        begin
          Chef::Log.info 'Setting up temporary keyring to compare keys'
          run_command "gpg2 --import --no-default-keyring --secret-keyring #{tmp_keyring_pri} --keyring #{tmp_keyring_pub}",
                      :user => @new_resource.for_user,
                      :input => @new_resource.key_contents
          draft = get_draft_key_details tmp_keyring_pub
          current = get_current_key_details
          if key_needs_to_be_installed draft, current
            converge_by "Importing key #{draft.username} into keyring" do
              remove_existing_keys draft, current
              run_command 'gpg2 --import',
                          :user => @new_resource.for_user,
                          :input => @new_resource.key_contents
            end
          end
        ensure
          run_command "shred -n 20 -z -u #{tmp_keyring_pri}", :user => @new_resource.for_user
          FileUtils.rm_rf tmp_keyring_pub
        end
      end
    end
  end
end