require 'mixlib/shellout'
require 'tempfile'

class Chef
  class Provider
    class GpgKeyManage < Chef::Provider
      def initialize(new_resource, run_context)
        super
      end

      def whyrun_supported?
        true
      end

      def load_current_resource
        @current_resource ||= Chef::Resource::GpgKeyManage.new(new_resource.name)
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
        contents = run_command("gpg2 --list-keys --fingerprint --no-default-keyring --keyring #{public_keyring_path}", :user => @new_resource.for_user)
        parser = BswTech::Gpg::GpgParser.new(contents.stdout)
        parser.keys[0]
      end

      def get_current_key_details()
        contents = run_command('gpg2 --list-keys --fingerprint', :user => @new_resource.for_user)
        parser = BswTech::Gpg::GpgParser.new(contents.stdout)
        parser.keys
      end

      def key_needs_to_be_installed(draft, current)
        current.all? {|x| x.fingerprint != draft.fingerprint}
      end

      def action_replace
        tmp_keyring_pri = Tempfile.new 'tmp_pri_keyring'
        tmp_keyring_pub = Tempfile.new 'tmp_pub_keyring'
        begin
          run_command("gpg2 --import --no-default-keyring --secret-keyring #{tmp_keyring_pri.path} --keyring #{tmp_keyring_pub.path}",
                      :user => @new_resource.for_user,
                      :input => @new_resource.key_contents)
          draft = get_draft_key_details tmp_keyring_pub.path
          current = get_current_key_details
          if key_needs_to_be_installed(draft, current)
            converge_by "Importing key #{draft.username} into keyring" do
              run_command 'gpg2 --import',
                          :user => @new_resource.for_user,
                          :input => @new_resource.key_contents
            end
          end
        ensure
          run_command "shred -n 20 -z #{tmp_keyring_pri.path}", :user => @new_resource.for_user
          tmp_keyring_pub.close!
          tmp_keyring_pri.close!
        end
      end
    end
  end
end