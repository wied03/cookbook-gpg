require 'tempfile'

class Chef
  class Provider
    class BaseGpgProvider < Chef::Provider
      include BswTech::Gpg::RecipeOrProvider

      def initialize(new_resource, run_context)
        super
        @keyring_specifier = BswTech::Gpg::KeyringSpecifier.new
        @gpg_interface = BswTech::Gpg::GpgInterface.new should_disable_trust_db_check
      end

      def whyrun_supported?
        true
      end

      def action_replace
        key_contents = get_key
        draft_key_header = @gpg_interface.get_key_header key_contents
        current = get_current_key_details draft_key_header.type
        if does_key_needs_to_be_installed draft_key_header, current
          converge_by "Importing key #{draft_key_header.username} into keyring #{keyring_file} for user #{@new_resource.for_user}" do
            remove_existing_keys draft_key_header, current
            import_keys key_contents
            if should_import_trust draft_key_header
              Chef::Log.info "Importing trust for key #{draft_key_header.username}"
              import_trust key_contents
            else
              Chef::Log.info "Skipping trust import for key #{draft_key_header.username}"
            end
          end
        end
      end

      def load_current_resource
        @current_resource.for_user(new_resource.for_user)
        @current_resource.keyring_file(new_resource.keyring_file)
        @current_resource
      end

      private

      def should_disable_trust_db_check
        resource_says = @new_resource.disable_trust_db_check
        return resource_says unless resource_says == nil
        keyring_file != :default
      end

      def should_import_trust(key_header)
        resource_says = @new_resource.force_import_owner_trust
        if resource_says != nil
          Chef::Log.debug "Using resource 'import trust' setting of #{resource_says}"
          return resource_says
        end
        if keyring_file == :default
          if key_header.type == :secret_key
            Chef::Log.debug 'Will import trust since default keyring is in use and a private key is being imported'
            true
          else
            Chef::Log.debug 'Will NOT import trust since the default keyring is in use, but a public key is being imported'
            false
          end
        else
          Chef::Log.debug 'Will NOT import trust since custom keyring is in use'
          false
        end
      end

      def import_trust(key_contents)
        @gpg_interface.import_trust @new_resource.for_user,
                                    key_contents,
                                    keyring_file
      end

      def import_keys(key_contents)
        @gpg_interface.import_keys @new_resource.for_user,
                                   key_contents,
                                   keyring_file
      end

      def get_current_key_details(type)
        @gpg_interface.get_current_installed_keys username=@new_resource.for_user,
                                                  type=type,
                                                  keyring=keyring_file
      end

      def keyring_file
        @new_resource.keyring_file || :default
      end

      def does_key_needs_to_be_installed(draft, current)
        Chef::Log.info 'Checking if key is already installed'
        current.all? { |x| x.fingerprint != draft.fingerprint }
      end

      def remove_existing_keys(draft_header, current_header)
        key_to_delete = current_header.find { |x| x.username == draft_header.username }
        if key_to_delete
          Chef::Log.info "Deleting existing key for #{key_to_delete.username} from keyring #{keyring_file} in order to replace it"
          @gpg_interface.delete_keys username=@new_resource.for_user,
                                     key_header_to_delete=current_header,
                                     keyring=keyring_file
        end
      end
    end
  end
end