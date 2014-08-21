require 'rspec'
$: << File.join(File.dirname(__FILE__), '../../..')
require 'libraries/helper_command_runner'

describe BswTech::CommandRunner do
  before(:each) do
    @commands = []
    original_new = Mixlib::ShellOut.method(:new)
    allow(Mixlib::ShellOut).to receive(:new) do |*args|
      command = original_new.call(*args)
      allow(command).to receive(:error!)
      allow(command).to receive(:run_command)
      allow(command).to receive(:stdout) do
        command.command.include?('sh') ? "/home/#{command.user}" : 'the output'
      end
      @commands << command
      command
    end
    @runner = BswTech::CommandRunner.new
  end

  it 'runs a command with no input and a default user' do
    # arrange

    # act
    result = @runner.run 'ls stuff'

    # assert
    expect(result).to eq 'the output'
    expect(@commands.length).to eq 1
    expect(@commands[0].command).to eq 'ls stuff'
    expect(@commands[0].input).to eq nil
    expect(@commands[0].user).to eq nil
  end

  it 'runs a command with no input and a specified user' do
    # arrange

    # act
    result = @runner.run 'ls stuff', 'joe'

    # assert
    expect(result).to eq 'the output'
    expect(@commands.length).to eq 2
    expect(@commands[0].command).to eq "/bin/sh -c \"echo -n ~joe\""
    expect(@commands[0].input).to eq nil
    expect(@commands[0].user).to eq 'joe'
    expect(@commands[1].command).to eq 'ls stuff'
    expect(@commands[1].input).to eq nil
    expect(@commands[1].user).to eq 'joe'
    expect(@commands[1].environment).to eq({
                                               'LC_ALL' => 'C',
                                               'HOME' => '/home/joe'
                                           })
  end

  it 'runs a command with input and a default user' do
    # act

    result = @runner.run 'ls stuff', :default, 'the input'

    # assert
    expect(result).to eq 'the output'
    expect(@commands.length).to eq 1
    expect(@commands[0].command).to eq 'ls stuff'
    expect(@commands[0].input).to eq 'the input'
    expect(@commands[0].user).to eq nil
  end

  it 'runs a command with no input and a specified user' do
    # arrange

    # act
    result = @runner.run 'ls stuff', 'joe', 'the input'

    # assert
    expect(result).to eq 'the output'
    expect(@commands.length).to eq 2
    expect(@commands[0].command).to eq "/bin/sh -c \"echo -n ~joe\""
    expect(@commands[0].input).to eq nil
    expect(@commands[0].user).to eq 'joe'
    expect(@commands[1].command).to eq 'ls stuff'
    expect(@commands[1].input).to eq 'the input'
    expect(@commands[1].user).to eq 'joe'
    expect(@commands[1].environment).to eq({
                                               'LC_ALL' => 'C',
                                               'HOME' => '/home/joe'
                                           })
  end
end
