class Chef
  class Provider
    class BswGpgLoadKeyFromDataBag < BaseGpgProvider
      provides :bsw_gpg_load_key_from_data_bag

      def initialize(new_resource, run_context)
        super
      end

      def load_current_resource
        @current_resource ||= Chef::Resource::BswGpgLoadKeyFromDataBag.new(new_resource.name)
        @current_resource.data_bag(new_resource.data_bag)
        @current_resource.item(new_resource.item)
        @current_resource.json_key(new_resource.json_key)
        super
      end

      def get_key
        item = Chef::DataBagItem.load(@new_resource.data_bag,
                                      @new_resource.item)
        item[@new_resource.json_key]
      end
    end
  end
end
