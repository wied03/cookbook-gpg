require 'mixlib/shellout'

module BswTech
  class CommandRunner
    def run(command,
            as_user=:default,
            input=nil)
      home_dir = home_dir_for_user as_user unless as_user == :default
      run_command_with_home_dir as_user,
                                command,
                                input,
                                home_dir
    end

    private

    def home_dir_for_user(username)
      result = run_command_with_home_dir as_user=username,
                                         command="/bin/sh -c \"echo -n ~#{username}\""
      result
    end

    def run_command_with_home_dir(as_user,
                                  command,
                                  input=nil,
                                  home_dir=nil)
      args = [command, {}]
      options = args.last
      options[:input] = input if input
      options[:user] = as_user unless as_user == :default
      options[:env] = {'HOME' => home_dir} if home_dir
      cmd = Mixlib::ShellOut.new(*args)
      cmd.run_command
      cmd.error!
      cmd.stdout
    end
  end
end