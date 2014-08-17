require 'mixlib/shellout'
require 'tempfile'

class Chef
  class Provider
    class BswGpgKeyManage < Chef::Provider
      include BswTech::Gpg::SharedKey

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
        @current_resource.chef_vault_info(new_resource.chef_vault_info)
        @current_resource.for_user(new_resource.for_user)
        @current_resource.key_type(new_resource.key_type)
        @current_resource
      end

      def get_current_secret_key_details()
        Chef::Log.info 'Retrieving currently installed secret keys'
        contents = run_command 'gpg2 --list-secret-keys --fingerprint'
        BswTech::Gpg::GpgParser.new.parse(:ring, contents.stdout)
      end

      def key_needs_to_be_installed(draft, current)
        Chef::Log.info 'Checking if key is already installed'
        current.all? { |x| x.fingerprint != draft.fingerprint }
      end

      def remove_existing_keys(draft, current)
        key_to_delete = current.find { |x| x.username == draft.username }
        if key_to_delete
          Chef::Log.info "Deleting existing key for #{key_to_delete.username} in order to replace it"
          run_command "gpg2 --delete-secret-and-public-key --batch --yes #{key_to_delete.fingerprint_no_whitespace}"
        end
      end

      def trust_key(key)
        run_command 'gpg2 --import-ownertrust', :input => "#{key.fingerprint_no_whitespace}:6:\n"
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

      def load_from_vault
        opts = @new_resource.chef_vault_info
        item = ChefVault::Item.load(opts[:data_bag], opts[:item])
        item[opts[:json_key]]
      end

      def action_replace
        key_contents = @new_resource.key_contents || load_from_vault
        draft = get_draft_key_from_string key_contents
        current = get_current_secret_key_details
        if key_needs_to_be_installed draft, current
          converge_by "Importing key #{draft.username} into keyring" do
            remove_existing_keys draft, current
            run_command 'gpg2 --import',
                        :input => key_contents
            trust_key draft
          end
        end
      end
    end
  end
end