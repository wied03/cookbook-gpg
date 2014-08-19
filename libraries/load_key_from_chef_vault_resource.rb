class Chef
  class Resource
    class BswGpgLoadKeyFromChefVault < LoadKeyBaseResource
      def initialize(name, run_context=nil)
        super
        @resource_name = :bsw_gpg_load_key_from_chef_vault
        @provider = Chef::Provider::BswGpgLoadKeyFromChefVault
      end

      def data_bag(arg=nil)
        set_or_return(:data_bag, arg, :kind_of => String, :required => true)
      end

      def item(arg=nil)
        set_or_return(:item, arg, :kind_of => String, :required => true)
      end

      def json_key(arg=nil)
        set_or_return(:json_key, arg, :kind_of => String, :required => true)
      end
    end
  end
end