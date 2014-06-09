require 'chefspec'

module BswTech
  module ChefSpec
    module LwrpTestHelper
      def generated_cookbook_path
        File.join File.dirname(__FILE__), 'gen_cookbooks'
      end

      def cookbook_path
        File.join generated_cookbook_path, generated_cookbook_name
      end

      def generated_cookbook_name
        'lwrp_gen'
      end

      def temp_lwrp_recipe(contents:,runner_options:{})
        create_temp_cookbook(contents)
        RSpec.configure do |config|
          config.cookbook_path = [*config.cookbook_path] << generated_cookbook_path
        end
        lwrps_full = [*lwrps_under_test].map do |lwrp|
          "#{cookbook_under_test}_#{lwrp}"
        end
        @chef_run = ::ChefSpec::Runner.new(runner_options.merge(step_into:lwrps_full))
        @chef_run.converge("#{generated_cookbook_name}::default")
      end

      def create_temp_cookbook(contents)
        the_path = cookbook_path
        recipes = File.join the_path, 'recipes'
        FileUtils.mkdir_p recipes
        File.open File.join(recipes, 'default.rb'), 'w' do |f|
          f << contents
        end
        File.open File.join(the_path, 'metadata.rb'), 'w' do |f|
          f << "name '#{generated_cookbook_name}'\n"
          f << "version '0.0.1'\n"
          f << "depends '#{cookbook_under_test}'\n"
        end
      end

      def cleanup
        FileUtils.rm_rf generated_cookbook_path
      end
    end
  end
end