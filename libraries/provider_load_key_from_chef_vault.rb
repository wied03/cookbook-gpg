class Chef
  class Provider
    class BswGpgLoadKeyFromChefVault < BaseGpgProvider
      def initialize(new_resource, run_context)
        super
      end

      def load_current_resource
        @current_resource ||= Chef::Resource::BswGpgLoadKeyFromChefVault.new(new_resource.name)
        @current_resource.data_bag(new_resource.data_bag)
        @current_resource.item(new_resource.item)
        @current_resource.json_key(new_resource.json_key)
        @current_resource.for_user(new_resource.for_user)
        @current_resource
      end

      def get_key
        item = ChefVault::Item.load(@new_resource.data_bag,
                                    @new_resource.item)
        item[@new_resource.json_key]
      end
    end
  end
end