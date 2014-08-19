class Chef
  class Resource
    class BswGpgLoadKeyFromString < LoadKeyBaseResource
      def initialize(name, run_context=nil)
        super
        @resource_name = :bsw_gpg_load_key_from_string
        @provider = Chef::Provider::BswGpgLoadKeyFromString
      end

      def key_contents(arg=nil)
        set_or_return(:key_contents, arg, :kind_of => String, :required => true)
      end
    end
  end
end