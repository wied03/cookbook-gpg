require 'mixlib/shellout'
require 'tempfile'

class Chef
  class Provider
    class GpgKeyManage < Chef::Provider
      def initialize(new_resource, run_context)
        super
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
        cmd.stdout
      end

      def action_replace
        tmp_keyring_pri = Tempfile.new 'tmp_pri_keyring'
        tmp_keyring_pub = Tempfile.new 'tmp_pub_keyring'
        begin
        run_command("gpg2 --import --no-default-keyring --secret-keyring #{tmp_keyring_pri.path} --keyring #{tmp_keyring_pub.path}",
                    :user => @new_resource.for_user,
                    :input => @new_resource.key_contents)
        converge_by 'foo' do
          puts 'actually run'
        end
        ensure
          tmp_keyring_pub.close!
          tmp_keyring_pri.close!
        end
      end
    end
  end
end