module BswTech
  module Gpg
    module RecipeOrProvider
      def cookbook_file_contents(source, cookbook_name)
        ::File.read(cookbook_file_location(source, cookbook_name))
      end

      def cookbook_file_location(source, cookbook_name)
        cookbook = run_context.cookbook_collection[cookbook_name]
        cookbook.preferred_filename_on_disk_location(node, :files, source)
      end
    end
  end
end

class Chef
  class Recipe
    include BswTech::Gpg::RecipeOrProvider
  end
end