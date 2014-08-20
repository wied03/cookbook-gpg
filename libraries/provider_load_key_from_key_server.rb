class Chef
  class Provider
    class BswGpgLoadKeyFromKeyServer < BaseGpgProvider
      def initialize(new_resource, run_context)
        super
      end

      def load_current_resource
        @current_resource ||= Chef::Resource::BswGpgLoadKeyFromKeyServer.new(new_resource.name)
        @current_resource.key_server(new_resource.key_server)
        @current_resource.key_id(new_resource.key_id)
        super
      end

      def get_key
        hkp = Hkp.new keyserver=@new_resource.key_server
        hkp.fetch id=@new_resource.key_id
      end
    end
  end
end