require 'mixlib/shellout'
require 'tempfile'

class Chef
  class Provider
    class BaseGpgProvider < Chef::Provider
      include BswTech::Gpg::SharedKey

      def initialize(new_resource, run_context)
        super
        # The way shellout works, the home directory is not set for the user and gpg needs that, easiest way is to use the shell
        @home_dir = run_command("/bin/sh -c \"echo -n ~#{@new_resource.for_user}\"").stdout
      end

      def whyrun_supported?
        true
      end

      def get_current_key_details(type)
        retriever = BswTech::Gpg::GpgRetriever.new
        executor = lambda do |command|
          contents = run_command command
          gpg_output = contents.stdout
          Chef::Log.debug "Output from GPG #{gpg_output}"
          gpg_output
        end
        retriever.get_current_installed_keys executor, type
      end

      def key_needs_to_be_installed(draft, current)
        Chef::Log.info 'Checking if key is already installed'
        current.all? { |x| x.fingerprint != draft.fingerprint }
      end

      def remove_existing_keys(draft, current)
        key_to_delete = current.find { |x| x.username == draft.username }
        if key_to_delete
          Chef::Log.info "Deleting existing key for #{key_to_delete.username} in order to replace it"
          delete = draft.type == :public_key ? '--delete-key' : '--delete-secret-and-public-key'
          run_command "gpg2 #{delete} --batch --yes #{key_to_delete.fingerprint}"
        end
      end

      def trust_key(key)
        run_command 'gpg2 --import-ownertrust', :input => "#{key.fingerprint}:6:\n"
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