require 'mixlib/shellout'
require 'tempfile'

class Chef
  class Provider
    class BaseGpgProvider < Chef::Provider
      include BswTech::Gpg::RecipeOrProvider

      def initialize(new_resource, run_context)
        super
        # The way shellout works, the home directory is not set for the user and gpg needs that, easiest way is to use the shell
        @home_dir = run_command("/bin/sh -c \"echo -n ~#{@new_resource.for_user}\"").stdout
        @keyring_specifier = BswTech::Gpg::KeyringSpecifier.new
      end

      def whyrun_supported?
        true
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

      def action_replace
        key_contents = get_key
        draft = get_draft_key_from_string key_contents
        current = get_current_key_details draft.type
        if does_key_needs_to_be_installed draft, current
          converge_by "Importing key #{draft.username} into keyring #{get_keyring}" do
            remove_existing_keys draft, current
            gpg_cmd = get_gpg_cmd(draft.type)
            run_command "#{gpg_cmd} --import",
                        :input => key_contents
            run_trust_key_command draft
          end
        end
      end

      def do_key_import(draft_key_details, key_contents)

      end

      def load_current_resource
        @current_resource.for_user(new_resource.for_user)
        @current_resource.keyring_file(new_resource.keyring_file)
        @current_resource
      end

      private

      def get_current_key_details(type)
        retriever = BswTech::Gpg::GpgRetriever.new
        executor = lambda do |command|
          contents = run_command command
          gpg_output = contents.stdout
          Chef::Log.debug "Output from GPG #{gpg_output}"
          gpg_output
        end
        keyring = get_keyring
        retriever.get_current_installed_keys executor, type, keyring
      end

      def get_keyring
        @new_resource.keyring_file || :default
      end

      def does_key_needs_to_be_installed(draft, current)
        Chef::Log.info 'Checking if key is already installed'
        current.all? { |x| x.fingerprint != draft.fingerprint }
      end

      def remove_existing_keys(draft, current)
        key_to_delete = current.find { |x| x.username == draft.username }
        if key_to_delete
          Chef::Log.info "Deleting existing key for #{key_to_delete.username} from keyring #{get_keyring} in order to replace it"
          delete = draft.type == :public_key ? '--delete-key' : '--delete-secret-and-public-key'
          gpg_command = get_gpg_cmd draft.type
          run_command "#{gpg_command} #{delete} --batch --yes #{key_to_delete.fingerprint}"
        end
      end

      def run_trust_key_command(key)
        gpg_command = get_gpg_cmd key.type
        run_command "#{gpg_command} --import-ownertrust", :input => "#{key.fingerprint}:6:\n"
      end

      def get_gpg_cmd(type)
        keyring_specifier = get_keyring_specifier type
        "gpg2#{keyring_specifier}".strip
      end

      def get_keyring_specifier(type)
        keyring = get_keyring
        keyring == :default ? ' ' : @keyring_specifier.get_custom_keyring(type, keyring)
      end
    end
  end
end